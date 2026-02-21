# PrivacyGuard

A lightweight Python tool that watches a folder and scans files for sensitive or personal data — catching things like credit card numbers, government IDs, passwords, and more before they leave your machine.

## Features

- **Live folder monitoring** — watches a directory and scans every new file as it arrives
- **One-time scan mode** — scan all existing files in a folder and exit
- **OCR support** — extracts and scans text from images (JPG, PNG, etc.) using Tesseract
- **Multi-format support** — scans PDFs, Word documents (DOCX), plain text, CSV, JSON, and more
- **ID document detection** — identifies government-issued IDs (driver's licenses, state IDs) by keyword clustering, even when no structured data pattern matches
- **Pattern matching** for:
  - Credit card numbers
  - SSN (US) and SIN (Canada)
  - Passport numbers
  - Email addresses and phone numbers
  - API keys, tokens, and private keys
  - Passwords in plaintext
  - IP addresses
  - Health and medical information

## Requirements

- Python 3.8+
- [Tesseract OCR](https://github.com/UB-Mannheim/tesseract/wiki) (for image scanning)

## Installation

```bash
pip install watchdog pytesseract pillow PyPDF2 python-docx
```

## Usage

**Watch a folder for new files:**
```bash
python main.py ~/Downloads
```

**Scan all existing files in a folder once:**
```bash
python main.py ~/Downloads --scan-once
```

## Output

Each file gets a report in the terminal:

```
============================================================
  Scanning: sample_id.png
============================================================
  File type : image
  Characters extracted: 312

  🚨 SENSITIVE DATA FOUND (1 type(s)):

    [Personal ID Document]
      Likely type : Driver's license or government-issued ID
      Keywords    : exp, dob, hgt, wgt, identification

  ✅ No other sensitive data patterns detected.
```

## Notes

- All scanning is done **locally** — no data is sent anywhere.
- Dependencies are optional; the scanner will skip unsupported formats gracefully if a library is missing.
