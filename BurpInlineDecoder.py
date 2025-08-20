# -*- coding: utf-8 -*-
# BurpInlineDecoder – Intruder GrepX decode with Grep-Extract style UI (compact, mutual exclusive) – Jython 2.7

from burp import IBurpExtender, ITab, IHttpListener, IBurpExtenderCallbacks
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
from javax.swing import (JPanel, JLabel, JTextField, JComboBox, JCheckBox)
from javax.swing.border import EmptyBorder
from javax.swing import BorderFactory
from javax.swing.event import DocumentListener
from java.awt.event import ItemListener
from java.util import WeakHashMap

import base64, binascii, zlib, json, re, urllib

__version__ = "1.0.0"

# ---------------- helpers ----------------

def to_text(b):
    if isinstance(b, unicode): return b
    try: return b.decode("utf-8")
    except Exception:
        try: return b.decode("latin-1")
        except Exception: return unicode(repr(b))

def to_bytes(x):
    return x.encode("latin-1") if isinstance(x, unicode) else x

def b64pad(s):
    m = len(s) % 4
    return s + ("=" * (4 - m) if m else "")

def dec_b64(s):      return base64.b64decode(b64pad(s))
def dec_b64url(s):   return base64.urlsafe_b64decode(b64pad(s))
def dec_hex(s):
    s = re.sub(r"[^0-9A-Fa-f]", "", s)
    return binascii.unhexlify(s)

def url_decode_multipass(s, max_pass=3):
    prev = s
    for _ in range(max_pass):
        cur = urllib.unquote_plus(prev)
        if cur == prev: break
        prev = cur
    return prev

def inflate_try(b):
    b = to_bytes(b)
    if len(b) >= 2 and b[:2] == "\x1f\x8b":
        import gzip, StringIO
        bio = StringIO.StringIO(b)
        gf = gzip.GzipFile(fileobj=bio, mode='rb')
        try: return gf.read()
        finally: gf.close()
    for w in (15, -15):
        try: return zlib.decompress(b, wbits=w)
        except Exception: pass
    raise ValueError("Not gzip/deflate")

def jwt_decode(s):
    parts = s.split(".")
    if len(parts) < 2: raise ValueError("Not a JWT")
    hdr = to_text(dec_b64url(parts[0]))
    pld = to_text(dec_b64url(parts[1]))
    try:  hdr = json.dumps(json.loads(hdr), indent=2)
    except Exception: pass
    try:  pld = json.dumps(json.loads(pld), indent=2)
    except Exception: pass
    return u"[JWT header]\n%s\n\n[JWT payload]\n%s" % (hdr, pld)

def json_pretty(s):
    if not isinstance(s, basestring): s = to_text(s)
    return json.dumps(json.loads(s), indent=2, ensure_ascii=False)

DECODERS = [
    "Auto (Base64)",
    "Base64",
    "Base64 (URL-safe)",
    "Hex -> Text",
    "URL-decode",
    "Gzip/Deflate",
    "JWT header+payload",
    "JSON pretty",
]

def auto_b64(s):
    try: return dec_b64(s)
    except Exception: return dec_b64url(s)

DEC_FN = {
    "Auto (Base64)":      lambda s: auto_b64(s),
    "Base64":             lambda s: dec_b64(s),
    "Base64 (URL-safe)":  lambda s: dec_b64url(s),
    "Hex -> Text":        lambda s: dec_hex(s),
    "URL-decode":         lambda s: url_decode_multipass(s).encode("utf-8"),
    "Gzip/Deflate":       lambda s: inflate_try(s),
    "JWT header+payload": lambda s: jwt_decode(s).encode("utf-8"),
    "JSON pretty":        lambda s: json_pretty(s).encode("utf-8"),
}

def sanitize_for_decoder(s, decoder_name):
    t = s.strip().strip('"').strip("'")
    if decoder_name in ("Auto (Base64)", "Base64"):
        m = re.findall(r"[A-Za-z0-9+/=]+", t)
        if m: t = max(m, key=len)
        t = b64pad(t)
    elif decoder_name == "Base64 (URL-safe)":
        m = re.findall(r"[-A-Za-z0-9_=]+", t)
        if m: t = max(m, key=len)
        t = b64pad(t)
    elif decoder_name == "Hex -> Text":
        t = re.sub(r"[^0-9A-Fa-f]", "", t)
    return t

# ---------------- small listeners for persistence ----------------

class _DocSave(DocumentListener):
    def __init__(self, savefn): self._save = savefn
    def insertUpdate(self, e): self._save()
    def removeUpdate(self, e): self._save()
    def changedUpdate(self, e): self._save()

class _ItemSave(ItemListener):
    def __init__(self, savefn): self._save = savefn
    def itemStateChanged(self, e): self._save()

# Mutual exclusivity controller
class _MutualToggle(ItemListener):
    def __init__(self, tab, who):  # who = "regex" or "between"
        self.tab = tab
        self.who = who
    def itemStateChanged(self, e):
        # Enforce exclusivity on user toggle
        if self.who == "regex":
            if self.tab.regexEnable.isSelected():
                self.tab.betweenEnable.setSelected(False)
        else:
            if self.tab.betweenEnable.isSelected():
                self.tab.regexEnable.setSelected(False)
        self.tab._syncModeEnable()
        self.tab._saveSettings()

# ---------------- UI tab ----------------

class GrepXTab(JPanel, ITab):
    def __init__(self, callbacks):
        JPanel.__init__(self, BorderLayout())
        self.cb = callbacks
        self.setBorder(EmptyBorder(6,6,6,6))

        # ===== Between delimiters panel (left)
        self.betweenEnable = JCheckBox("Define start and end", True)
        self.startAfterLbl = JLabel("Start after expression:")
        self.startAfterTf  = JTextField('Set-Cookie: cognito-fl="', 30)
        self.endAtLbl      = JLabel("End at delimiter:")
        self.endAtTf       = JTextField('";', 20)

        pBetweenInner = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(4,4,4,4)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL
        row = [0]
        def add_row(lbl, comp):
            gbc.gridx, gbc.gridy, gbc.weightx = 0, row[0], 0.0; pBetweenInner.add(lbl, gbc)
            gbc.gridx, gbc.weightx = 1, 1.0; pBetweenInner.add(comp, gbc)
            row[0] += 1
        add_row(self.startAfterLbl, self.startAfterTf)
        add_row(self.endAtLbl, self.endAtTf)

        pBetween = JPanel(BorderLayout())
        pBetween.setBorder(BorderFactory.createTitledBorder("Define start and end"))
        pBetween.add(self.betweenEnable, BorderLayout.NORTH)
        pBetween.add(pBetweenInner, BorderLayout.CENTER)

        # ===== Regex panel (right)
        self.regexEnable = JCheckBox("Extract from regex group", False)
        self.regexTf     = JTextField(r'Set-Cookie:\s*cognito-fl="([^"]+)"', 36)
        self.caseSens    = JCheckBox("Case sensitive", False)

        pRegexInner = JPanel(GridBagLayout())
        row2 = [0]
        def add_row2(comp):
            gbc.gridx, gbc.gridy, gbc.weightx = 0, row2[0], 1.0; pRegexInner.add(comp, gbc)
            row2[0] += 1
        add_row2(self.regexTf)
        add_row2(self.caseSens)

        pRegex = JPanel(BorderLayout())
        pRegex.setBorder(BorderFactory.createTitledBorder("Extract from regex group"))
        pRegex.add(self.regexEnable, BorderLayout.NORTH)
        pRegex.add(pRegexInner, BorderLayout.CENTER)

        # ===== Decoder & scope/options
        self.decoder   = JComboBox(DECODERS)
        self.maxOut    = JTextField("300", 6)
        self.inHdrs    = JCheckBox("Search headers", True)
        self.inBody    = JCheckBox("Search body", False)
        self.replace   = JCheckBox("Replace Comment (not append)", True)
        self.doHl      = JCheckBox("Highlight row", True)
        self.enable    = JCheckBox("Enable live decode (Intruder only)", True)

        pOptions = JPanel(GridBagLayout())
        row3 = [0]
        def add_row3(lbl, comp):
            gbc.gridx, gbc.gridy, gbc.weightx = 0, row3[0], 0.0; pOptions.add(JLabel(lbl), gbc)
            gbc.gridx, gbc.weightx = 1, 1.0; pOptions.add(comp, gbc)
            row3[0] += 1
        add_row3("Decoder:", self.decoder)
        add_row3("Comment max length:", self.maxOut)
        add_row3("Scope:", self._hbox(self.inHdrs, self.inBody))
        add_row3("Options:", self._hbox(self.replace, self.doHl))
        add_row3("", self.enable)

        # ===== Layout (compact at top)
        configGrid = JPanel(GridBagLayout())
        gbcMain = GridBagConstraints()
        gbcMain.insets = Insets(6,6,6,6)
        gbcMain.anchor = GridBagConstraints.NORTHWEST
        gbcMain.fill = GridBagConstraints.BOTH

        gbcMain.gridx, gbcMain.gridy, gbcMain.weightx, gbcMain.weighty = 0, 0, 1.0, 0.0
        configGrid.add(pBetween, gbcMain)
        gbcMain.gridx = 1
        configGrid.add(pRegex, gbcMain)
        gbcMain.gridx = 0; gbcMain.gridy = 1; gbcMain.gridwidth = 2; gbcMain.weightx = 1.0
        configGrid.add(pOptions, gbcMain)

        outer = JPanel(BorderLayout())
        outer.add(configGrid, BorderLayout.NORTH)  # pin to top
        self.add(outer, BorderLayout.CENTER)

        # State
        self._compiled = None
        self._cache = WeakHashMap()

        # Persistence & wiring
        self._loadSettings()
        self._wirePersistence()
        self._normalizeExclusiveOnLoad()
        self._syncModeEnable()
        self._recompile()

    # ----- helpers -----
    def _hbox(self, *comps):
        p = JPanel()
        for c in comps: p.add(c)
        return p

    def getTabCaption(self): return "BurpInlineDecoder"
    def getUiComponent(self): return self

    # ===== exclusivity & enable/disable
    def _syncModeEnable(self):
        reOn  = self.regexEnable.isSelected()
        beOn  = self.betweenEnable.isSelected()
        for comp in (self.regexTf, self.caseSens):
            comp.setEnabled(reOn)
        for comp in (self.startAfterTf, self.endAtTf):
            comp.setEnabled(beOn)
        if not reOn and not beOn:
            # default: keep 'between' on
            self.betweenEnable.setSelected(True)
            for comp in (self.startAfterTf, self.endAtTf):
                comp.setEnabled(True)

    def _normalizeExclusiveOnLoad(self):
        # If settings persisted both as 'on', prefer regex (or change to your taste)
        if self.regexEnable.isSelected() and self.betweenEnable.isSelected():
            self.betweenEnable.setSelected(False)

    # ----- persistence -----
    def _saveSettings(self):
        setv = self.cb.saveExtensionSetting
        setv("betweenOn", "1" if self.betweenEnable.isSelected() else "0")
        setv("startAfter", self.startAfterTf.getText())
        setv("endAt", self.endAtTf.getText())
        setv("regexOn", "1" if self.regexEnable.isSelected() else "0")
        setv("regex", self.regexTf.getText())
        setv("case", "1" if self.caseSens.isSelected() else "0")
        setv("decoder", self.decoder.getSelectedItem())
        setv("inHdrs", "1" if self.inHdrs.isSelected() else "0")
        setv("inBody", "1" if self.inBody.isSelected() else "0")
        setv("maxOut", self.maxOut.getText())
        setv("replace", "1" if self.replace.isSelected() else "0")
        setv("doHl", "1" if self.doHl.isSelected() else "0")
        setv("enable", "1" if self.enable.isSelected() else "0")
        self._syncModeEnable()
        self._recompile()

    def _loadSettings(self):
        get = self.cb.loadExtensionSetting
        def getOr(k, d):
            v = get(k)
            return d if v is None else v
        self.betweenEnable.setSelected(getOr("betweenOn","1")=="1")
        self.startAfterTf.setText(getOr("startAfter",'Set-Cookie: cognito-fl="'))
        self.endAtTf.setText(getOr("endAt",'";'))
        self.regexEnable.setSelected(getOr("regexOn","0")=="1")
        self.regexTf.setText(getOr("regex", r'Set-Cookie:\s*cognito-fl="([^"]+)"'))
        self.caseSens.setSelected(getOr("case","0")=="1")
        dec = getOr("decoder", "Auto (Base64)")
        try: self.decoder.setSelectedItem(dec)
        except: pass
        self.inHdrs.setSelected(getOr("inHdrs","1")=="1")
        self.inBody.setSelected(getOr("inBody","0")=="1")
        self.maxOut.setText(getOr("maxOut","300"))
        self.replace.setSelected(getOr("replace","1")=="1")
        self.doHl.setSelected(getOr("doHl","1")=="1")
        self.enable.setSelected(getOr("enable","1")=="1")

    def _wirePersistence(self):
        saver = _DocSave(self._saveSettings)
        for tf in (self.startAfterTf, self.endAtTf, self.regexTf, self.maxOut):
            tf.getDocument().addDocumentListener(saver)
        # generic saves
        for cb in (self.caseSens, self.inHdrs, self.inBody, self.replace, self.doHl, self.enable):
            cb.addItemListener(_ItemSave(self._saveSettings))
        self.decoder.addItemListener(_ItemSave(self._saveSettings))
        # mutual exclusivity listeners
        self.regexEnable.addItemListener(_MutualToggle(self, "regex"))
        self.betweenEnable.addItemListener(_MutualToggle(self, "between"))

    # ----- regex cache -----
    def _recompile(self):
        flags = 0 if self.caseSens.isSelected() else re.IGNORECASE
        try:
            self._compiled = re.compile(self.regexTf.getText(), flags|re.DOTALL)
        except Exception:
            self._compiled = None

    # ----- getters -----
    def isEnabled(self):  return self.enable.isSelected()
    def useRegex(self):   return self.regexEnable.isSelected()
    def useBetween(self): return self.betweenEnable.isSelected()
    def getFrom(self):    return self.startAfterTf.getText()
    def getTo(self):      return self.endAtTf.getText()
    def getRegex(self):   return self.regexTf.getText()
    def getDecoder(self): return self.decoder.getSelectedItem()
    def searchHdrs(self): return self.inHdrs.isSelected()
    def searchBody(self): return self.inBody.isSelected()
    def isCase(self):     return self.caseSens.isSelected()
    def maxOutLen(self):
        try: return max(1, min(20000, int(self.maxOut.getText().strip())))
        except: return 300
    def replaceComment(self): return self.replace.isSelected()
    def doHighlight(self):    return self.doHl.isSelected()

# --------------- Intruder listener ----------------

class LiveDecoder(IHttpListener):
    def __init__(self, callbacks, tab):
        self.cb = callbacks
        self.helpers = callbacks.getHelpers()
        self.tab = tab

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest: return
        if toolFlag != IBurpExtenderCallbacks.TOOL_INTRUDER: return
        if not self.tab.isEnabled(): return

        resp = messageInfo.getResponse()
        if resp is None: return
        rinfo = self.helpers.analyzeResponse(resp)

        hay = []
        if self.tab.searchHdrs():
            hay.append(u"\r\n".join([to_text(h) for h in rinfo.getHeaders()]))
        if self.tab.searchBody():
            hay.append(to_text(resp[rinfo.getBodyOffset():]))
        if not hay: return

        # Extract using active panel
        extracted = None

        if self.tab.useRegex():
            pat = self.tab._compiled
            if pat is None: return
            for h in hay:
                m = pat.search(h)
                if m and m.groups():
                    extracted = m.group(1)
                    break
        elif self.tab.useBetween():
            start = self.tab.getFrom()
            end   = self.tab.getTo()
            if not start: return
            flags = 0 if self.tab.isCase() else re.IGNORECASE
            for h in hay:
                m = re.search(re.escape(start), h, flags)
                if not m: continue
                sidx = m.end()
                if end:
                    m2 = re.search(re.escape(end), h[sidx:], flags)
                    if not m2: continue
                    eidx = sidx + m2.start()
                    extracted = h[sidx:eidx]; break
                else:
                    extracted = h[sidx:]; break

        if not extracted: return

        # Sanitize + Decode (truncate after decode)
        dec_name = self.tab.getDecoder()
        try:
            cleaned = sanitize_for_decoder(extracted, dec_name)
            decoded = to_text(DEC_FN[dec_name](cleaned))
            out = decoded[: self.tab.maxOutLen()]
        except Exception as e:
            out = u"<decode error: %s>" % to_text(str(e))

        # Idempotent write with cache
        last = self.tab._cache.get(messageInfo)
        if last == out: return
        self.tab._cache.put(messageInfo, out)

        cur = messageInfo.getComment() or u""
        newc = out if (self.tab.replaceComment() or not cur) else (cur + (u" | " if cur else u"") + out)
        messageInfo.setComment(newc)
        if self.tab.doHighlight():
            messageInfo.setHighlight("cyan")

# --------------- Burp entry ----------------

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("BurpInlineDecoder v%s" % __version__)
        tab = GrepXTab(callbacks)
        callbacks.addSuiteTab(tab)
        callbacks.registerHttpListener(LiveDecoder(callbacks, tab))

