"""
config.py
Manages persistent app configuration stored in config.json.
The archive password is kept in memory only — never written to disk.
"""

import json
import os

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

_defaults = {
    "watch_folder": os.path.expanduser("~/Downloads"),
    "archive_path": "",   # path to the user's existing encrypted ZIP
}

_config: dict = {}

# Archive password is intentionally NOT persisted to disk
_archive_password: str = ""


def load():
    print(f"[config] Loading config from {CONFIG_FILE}...")
    """Load config from disk. Falls back to defaults if file doesn't exist."""
    global _config
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                _config = json.load(f)
        except Exception:
            _config = dict(_defaults)
    else:
        _config = dict(_defaults)


def save():
    """Persist config to disk (password is never included)."""
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(_config, f, indent=2)
    except Exception as e:
        print(f"[config] Could not save config: {e}")


def get(key: str, default=None):
    print(_config)
    return _config.get(key, _defaults.get(key, default))


def set(key: str, value):
    _config[key] = value


def get_archive_password() -> str:
    return _archive_password


def set_archive_password(pw: str):
    global _archive_password
    _archive_password = pw


# Load on import
load()
