# BurpInlineDecoder

**BurpInlineDecoder** is a Burp Suite extension that extracts and decodes values from HTTP responses **during Intruder attacks** and writes the result into the **Comment** column—so you can sort, grep, and reason about responses without leaving the Intruder UI.

It mirrors the familiar *Grep – Extract* experience: choose **between delimiters** *or* a **regex capture group**, then pick a decoder (Base64, URL-safe Base64, Hex → Text, URL decode, Gzip/Deflate, JWT header+payload, JSON pretty).

<p align="center">
  <img src="assets/ui-compact.png" alt="BurpInlineDecoder configuration UI (compact layout)" width="900">
</p>

<p align="center">
  <img src="assets/intruder-results.png" alt="Decoded output in the Intruder results Comment column" width="900">
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
- ✍️ **Comment control**: *Replace Comment (not append)* or append to existing comments.
- 🎨 **Optional row highlight** for quick visual scanning.
- 💾 **Settings persist** across Burp sessions.

---

## Compatibility

- Burp Suite Professional / Community
- Jython (Burp → Extender → Options → Python Environment)
- Tested with Jython 2.7.x

---

## Installation

1. Install **Jython** and point Burp to the JAR (Burp → **Extender** → **Options** → Python Environment).
2. Clone this repository:
   ```bash
   git clone https://github.com/AI-Pentest/BurpInlineDecoder.git
   cd BurpInlineDecoder
