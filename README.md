# BurpInlineDecoder

**BurpInlineDecoder** is a Burp Suite extension that automatically extracts and decodes values from HTTP responses and writes them into the **Intruder Comment** field.  
Supports multiple decoding methods including Base64, URL-safe, and Hex.

## Features
- Extracts substrings between user-defined delimiters (From → To).
- Automatically decodes values (Base64, URL, Hex).
- Injects decoded values directly into the Intruder Comment field.
- Simplifies testing of hidden tokens (e.g., AWS Cognito cookies, reset codes, JWT fragments).
- Saves time during password reset, token analysis, and fuzzing workflows.

## Installation
1. Install **Jython** and configure it under Burp → Extender → Options.
2. Clone this repository:
   ```bash
   git clone https://github.com/Al-Pentest/BurpInlineDecoder.git
