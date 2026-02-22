# 🛡️ PrivacyGuard
### Team: Marmot-Hacker

A lightweight Python desktop app that runs silently in your system tray, watches one or more folders, and scans every new file for sensitive or personal data - catching things like credit card numbers, government IDs, API keys, and more before they leave your machine.

## Features

- **System tray app** - runs in the background with a shield icon; right-click for quick access to settings, restart, or quit
- **Settings window** - configure watch folders, an existing encrypted archive, and archive password through a clean UI
- **Multiple watch folders** - monitor as many folders as you want simultaneously, each in its own background thread
- **Live folder monitoring** - scans every new file as it arrives in any watched folder
- **One-time scan mode** - scan all existing files in your configured folders and exit
- **Encrypted ZIP protection** - when sensitive data is detected, you can:
  - Add the file directly to an existing password-protected ZIP archive
  - Create a new encrypted ZIP on the spot
  - Optionally delete the original unencrypted file after archiving
- **OCR support** - extracts and scans text from images (JPG, PNG, etc.) using Tesseract
- **Multi-format support** - scans PDFs, Word documents (DOCX), plain text, CSV, JSON, XML, logs, and more
- **ID document detection** - identifies government-issued IDs (driver's licenses, state IDs) by keyword clustering, even when no structured data pattern matches
- **Pattern matching** for:
  - Credit card numbers
  - SSN (US) and SIN (Canada)
  - Passport numbers
  - Dates of birth
  - Email addresses and phone numbers
  - API keys, tokens, and private keys
  - Passwords in plaintext
  - IP addresses
  - Health and medical information

## Requirements

- Python 3.10+
- [Tesseract OCR](https://github.com/UB-Mannheim/tesseract/wiki) - included in `Tesseract-OCR/` folder

## Installation

```bash
pip install watchdog pytesseract pillow PyPDF2 python-docx pystray
```

## Usage

**Run the app (system tray + live monitoring):**
```bash
python main.py
```

**Scan all existing files in the configured folders once and exit:**
```bash
python main.py --scan-once
```

## Configuration

Settings are stored in `config.json` and managed through the settings window (right-click tray icon -> Open Settings):

| Setting | Description |
|---|---|
| **Watch Folders** | One or more folders to monitor. Changes take effect after restart. |
| **Existing Encrypted Archive** | Optional path to an existing ZIP. Lets you add flagged files directly to it. |
| **Archive Password** | Held in memory only - never written to disk. Must be re-entered after restart. |

## How it works

1. PrivacyGuard starts and launches a watcher thread for each configured folder.
2. When a new file appears, it extracts readable text (via OCR, PDF parsing, or plain text reading).
3. The text is checked against regex patterns for sensitive data types and an ID keyword cluster.
4. If anything is found, a popup appears on top of all windows summarising the findings and offering to encrypt the file.

## Terminal output example

```
============================================================
  Scanning: passport_scan.png
============================================================
  File type : image
  Characters extracted: 287

  SENSITIVE DATA FOUND (2 type(s)):

    [Personal ID Document]
      Likely type : Driver's license or government-issued ID
      Keywords    : date of birth, exp, identification

    [Passport Number]
      Occurrences : 1
      Sample match: AB1234567
```

## Notes

- All scanning is done **locally** - no data is sent anywhere.
- Optional dependencies are skipped gracefully - if a library is missing, that file type is simply not scanned.
- The archive password is intentionally never saved to disk for security.
