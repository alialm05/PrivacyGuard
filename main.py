"""
Privacy File Scanner - Prototype
Watches a folder and scans new files for sensitive information.

Install dependencies:
    pip install watchdog pytesseract pillow PyPDF2 python-docx

You also need Tesseract installed on your system:
    Mac:     brew install tesseract
    Ubuntu:  sudo apt install tesseract-ocr
    Windows: https://github.com/UB-Mannheim/tesseract/wiki
"""

import os
import re
import time
import threading
from pathlib import Path

from ui import show_sensitive_popup

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Optional imports (gracefully skip if not installed) ---
try:
    import pytesseract
    from PIL import Image
    pytesseract.pytesseract.tesseract_cmd = os.path.join(BASE_DIR, "Tesseract-OCR", "tesseract.exe")
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False
    print("[WARN] pytesseract/Pillow not installed. Image scanning disabled.")

try:
    from PyPDF2 import PdfReader
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("[WARN] PyPDF2 not installed. PDF scanning disabled.")

try:
    from docx import Document
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False
    print("[WARN] python-docx not installed. DOCX scanning disabled.")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("[WARN] watchdog not installed. Live monitoring disabled.")


#  SENSITIVE DATA PATTERNS
# ─────────────────────────────────────────

PATTERNS = {
    "Credit Card Number":       r"\b(?:\d[ -]?){13,16}\b",
    "SSN (US)":                 r"\b\d{3}-\d{2}-\d{4}\b",
    "Phone Number":             r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
    "Email Address":            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "API Key / Token":          r"(?i)(api[_-]?key|token|secret|bearer)[^\n]{0,10}[=:]\s*[A-Za-z0-9\-_]{16,}",
    "Private Key Header":       r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Password in Text":         r"(?i)password\s*[=:]\s*\S+",
    "IP Address":               r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "Passport Number":          r"\b[A-Z]{1,2}[0-9]{6,9}\b",
    "Driver's License Keywords":r"(?i)(driver.?s?\s+license|DL#|DOB|date of birth|expir)",
    "Health/Medical Info":      r"(?i)(diagnosis|prescription|patient\s+id|medicare|medicaid|insurance\s+id)",
    "SIN (Canada)":             r"\b\d{3}\s\d{3}\s\d{3}\b",
    "Date of Birth":            r"\b\d{1,4}\s*[-/]\s*\d{1,2}\s*[-/]\s*\d{1,4}\b",
}

# ID document keyword clusters — if enough appear together it's likely an ID scan
# Includes both full words and common abbreviations found on government-issued IDs
ID_KEYWORDS = [
    "license", "dob", "exp",
    "class", "sex", "height", "weight", "address", "issued",
    "hgt", "wgt", "iss",            # abbreviations for height, weight, issued
    "ln", "fn",                      # last name / first name labels
    "identification", "donor",       # common ID card labels
    "dl#", "id#", "state id",        # explicit ID markers
    "legal name", "date of birth",     # more verbose keywords
    "classified", "confidential", "for official use only"  # security markings often on IDs
]




#  TEXT EXTRACTION
# ─────────────────────────────────────────

def extract_text_from_image(filepath):
    """Use OCR to extract text from an image file."""
    if not OCR_AVAILABLE:
        return ""
    try:
        img = Image.open(filepath)
        text = pytesseract.image_to_string(img)
        print(f"  [OCR] Characters extracted: {text}")
        return text
    except Exception as e:
        print(f"  [!] Could not OCR image: {e}")
        return ""

def extract_text_from_pdf(filepath):
    """Extract text from a PDF file."""
    if not PDF_AVAILABLE:
        return ""
    try:
        reader = PdfReader(filepath)
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except Exception as e:
        print(f"  [!] Could not read PDF: {e}")
        return ""

def extract_text_from_docx(filepath):
    """Extract text from a Word document."""
    if not DOCX_AVAILABLE:
        return ""
    try:
        doc = Document(filepath)
        return "\n".join(p.text for p in doc.paragraphs)
    except Exception as e:
        print(f"  [!] Could not read DOCX: {e}")
        return ""

def extract_text_from_txt(filepath):
    """Read plain text files."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        print(f"  [!] Could not read file: {e}")
        return ""

def extract_text(filepath):
    """Route file to the right extractor based on extension."""
    ext = Path(filepath).suffix.lower()
    if ext in [".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"]:
        return extract_text_from_image(filepath), "image"
    elif ext == ".pdf":
        return extract_text_from_pdf(filepath), "pdf"
    elif ext == ".docx":
        return extract_text_from_docx(filepath), "docx"
    elif ext in [".txt", ".csv", ".json", ".xml", ".log", ".md"]:
        return extract_text_from_txt(filepath), "text"
    else:
        return "", "unsupported"



#  SCANNING LOGIC
# ─────────────────────────────────────────

def check_id_document(text):
    """Check if enough ID-related keywords appear to suggest a photo of an ID."""
    lower = text.lower()
    matches = []
    for kw in ID_KEYWORDS:
        if kw in lower:
            matches.append(kw)
    return len(matches) >= 2, matches  # 2+ keywords = likely an ID doc

def scan_text(text):
    """Run all regex patterns against extracted text. Returns list of findings."""
    findings = []
    for label, pattern in PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            # Truncate match display for cleanliness
            sample = matches[0] if isinstance(matches[0], str) else matches[0][0]
            sample = sample.strip()[:60]
            findings.append((label, sample, len(matches)))
    return findings

def scan_file(filepath):
    """Main function: extract text from a file and check for sensitive data."""
    filepath = str(filepath)
    filename = os.path.basename(filepath)

    print(f"\n{'='*60}")
    print(f"  Scanning: {filename}")
    print(f"{'='*60}")

    # Small delay to make sure file is fully written before reading
    time.sleep(0.5)

    text, filetype = extract_text(filepath)

    if filetype == "unsupported":
        print(f"  [SKIP] Unsupported file type.")
        return

    if not text.strip():
        print(f"  [OK] No readable text found.")
        return

    print(f"  File type : {filetype}")
    print(f"  Characters extracted: {len(text)}")

    # is it a ID document?
    is_id, id_keywords = check_id_document(text)

    # pattern matching to check other sensitive data like SIN or IP adress, ID documents might not have this
    findings = scan_text(text)

    if is_id or findings:
        total = len(findings) + (1 if is_id else 0)
        print(f"\n  🚨 SENSITIVE DATA FOUND ({total} type(s)):\n")
        if is_id:
            print(f"    [Personal ID Document]")
            print(f"      Likely type : Driver's license or government-issued ID")
            print(f"      Keywords    : {', '.join(id_keywords)}")
            print()
        for label, sample, count in findings:
            print(f"    [{label}]")
            print(f"      Occurrences : {count}")
            print(f"      Sample match: {sample}")
            print()
        # Show popup with details and ask if user wants to encrypt
        show_sensitive_popup(filepath, findings, is_id)
    else:
        print(f"\n  ✅ No sensitive data detected.")



#  FOLDER WATCHER
# ─────────────────────────────────────────

MAX_CACHE_SIZE = 1000
scanned_files = set()  # avoid scanning the same file multiple times (e.g. moved files)

def add_to_scanned(filepath):
    if len(scanned_files) >= MAX_CACHE_SIZE:
        scanned_files.clear()
    scanned_files.add(filepath)


class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and event.src_path not in scanned_files:
            add_to_scanned(event.src_path)
            scan_file(event.src_path)

    def on_moved(self, event):
        # Catches files moved/transferred into the watched folder
        if not event.is_directory and event.dest_path not in scanned_files:
            add_to_scanned(event.dest_path)
            scan_file(event.dest_path)


def watch_folder(folder_path):
    """Start watching a folder for new files."""
    folder_path = os.path.expanduser(folder_path)

    if not os.path.exists(folder_path):
        print(f"[ERROR] Folder does not exist: {folder_path}")
        return

    print(f"\n🔍 Privacy Scanner Started")
    print(f"   Watching: {folder_path}")
    print(f"   Press Ctrl+C to stop.\n")

    if WATCHDOG_AVAILABLE:
        handler = DownloadHandler()
        observer = Observer()
        observer.schedule(handler, folder_path, recursive=False)
        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    else:
        print("[ERROR] watchdog not installed. Cannot watch folder.")
        print("        Run: pip install watchdog")


def scan_folder_once(folder_path):
    """Scan all existing files in a folder (useful for testing)."""
    folder_path = os.path.expanduser(folder_path)
    print(f"\n🔍 Scanning all files in: {folder_path}\n")
    for filename in os.listdir(folder_path):
        filepath = os.path.join(folder_path, filename)
        if os.path.isfile(filepath):
            scan_file(filepath)


#  ENTRY POINT
# ─────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import config
    import tray

    if "--scan-once" in sys.argv:
        # Headless one-shot scan (useful for testing)
        folders = config.get_watch_folders()
        for folder in folders:
            scan_folder_once(folder)
    else:
        # Start one watcher thread per configured folder
        for watch_folder_path in config.get_watch_folders():
            threading.Thread(
                target=watch_folder,
                args=(watch_folder_path,),
                daemon=True
            ).start()

        # Launch the settings window + system tray on the main thread
        # (blocks here until the user clicks Quit in the tray)
        tray.launch()