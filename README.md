# BurpInlineDecoder

**BurpInlineDecoder** is a Burp Suite extension that extracts and decodes values from HTTP responses **during Intruder attacks** and writes the result into the **Comment** column, so you can sort, grep, and reason about responses without leaving the Intruder UI.

It mirrors the familiar *Grep – Extract* experience: choose **between delimiters** *or* a **regex capture group**, then pick a decoder (Base64, URL-safe Base64, Hex → Text, URL decode, Gzip/Deflate, JWT header+payload, JSON pretty).

<p align="center">
  <img src="ui-compact.png" alt="BurpInlineDecoder configuration UI (compact layout)" width="900">
</p>

<p align="center">
  <img src="intruder-results.png" alt="Decoded output in the Intruder results Comment column" width="900">
</p>

---

## Features

- 📌 **Inline decode into Intruder**: results show up in **Comment**, right next to payload/length/status.
- 🎯 **Two extraction modes** (mutually exclusive, like Grep-Extract):
  - **Between delimiters**: *Start after* / *End at*.
  - **Regex group**: your regex; the first capturing group is extracted.
- 🧰 **Decoders included**
  - Auto (Base64), Base64, Base64 (URL-safe)
  - Hex → Text, URL-decode
  - Gzip/Deflate (zlib & gzip heuristics)
  - JWT header + payload (pretty-printed JSON)
  - JSON pretty
- 🧹 **Input sanitization** for Base64/Hex (pads/normalizes common cases).
- ✍️ **Comment control**: *Replace Comment* or append to existing comments.
- 🎨 **Optional row highlight** for quick visual scanning.
- 💾 **Settings persist** across Burp sessions.

---

## Compatibility

- Burp Suite Professional / Community (latest versions)
- Requires **Jython 2.7.x** (Burp → Extender → Options → Python Environment)

---

## Installation

1. Install **Jython 2.7.x** and point Burp to the JAR (Burp → **Extender** → **Options** → Python Environment).
2. Clone this repository:
   ```bash
   git clone https://github.com/AI-Pentest/BurpInlineDecoder.git
   cd BurpInlineDecoder
   ```
3. In Burp, go to **Extender → Extensions → Add**:
   - **Extension type**: Python
   - **Extension file**: `BurpInlineDecoder.py`

---

## Usage

1. Choose **one** extraction mode:
   - **Between delimiters** (start/end), **or**
   - **Regex group** (first capturing group).
   > Only one can be active at a time.

2. Pick a **Decoder**:
   - “Auto (Base64)” tries standard → URL-safe Base64.
   - “Hex → Text” strips non-hex chars.
   - “Gzip/Deflate” tries gzip then zlib.
   - “JWT header+payload” pretty-prints the first two JWT parts.
   - “JSON pretty” pretty-prints valid JSON.

3. Scope options:
   - **Search headers** and/or **Search body**.

4. Options:
   - **Replace Comment (not append)**
   - **Highlight row**
   - **Comment max length** (cap long values)

5. Run Intruder → decoded values appear in the **Comment** column.

---

## Tips

- Base64/Hex sanitization handles padding and common junk chars.
- JWT preview: grep token with regex → decode with **JWT header+payload**.
- Large blobs: decode compressed JSON with **Gzip/Deflate**.
- Append vs Replace: keep notes vs deterministic sorting.

---

## Troubleshooting

- **Incorrect padding**: use Auto (Base64).
- **No output**: check scope and extraction mode.
- **Both modes**: mutually exclusive by design.
- **Double-encoding**: try URL-decode first, then Gzip/Deflate.

---

## Development

Main file: `BurpInlineDecoder.py`

Key components:
- UI tab (`GrepXTab`) with Grep-Extract-style panels.
- `LiveDecoder` (IHttpListener) injects decoded values into Intruder comments.
- Decoder functions: Base64, URL-safe Base64, Hex, URL decode, Deflate/Gzip, JWT, JSON pretty.

Currently targets Intruder responses only (PRs welcome for more tools).

---

## License

MIT — see [LICENSE](LICENSE).

---

### ✅ Improvements made
- Added explicit **Jython version requirement** in Compatibility/Installation.
- Simplified some Usage bullet points for clarity.
- Noted **comment max length option** up front (store reviewers like clarity on limits).
- Polished consistency (e.g., “Replace Comment” → always same phrasing).
- Confirmed short/long descriptions are extractable for submission.

This is now in **BApp-ready** format.

