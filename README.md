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
   
3. In Burp, go to **Extender → Extensions → Add**.
   - Extension Type: Python
   - Extension file: `BurpInlineDecoder.py`

## Usage
- Adjust the **From** and **To** delimiters in the code for your target strings.  
- Run Intruder — decoded values will appear in the **Comment** column.

## License
MIT License. See [LICENSE](LICENSE).
