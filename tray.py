"""
tray.py
Manages the main PrivacyGuard settings window and the system tray icon.

The window can be closed (hidden) while the app keeps running in the tray.
Right-click the tray icon → Open Settings or Quit.
"""


from logging import root
import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

from PIL import Image, ImageDraw
import pystray

import config

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Module-level references ────────────────────────────────────────────────────
_root: tk.Tk | None = None      # the one persistent Tk root
_tray_icon: pystray.Icon | None = None


# ─────────────────────────────────────────
#  TRAY ICON IMAGE  (drawn with PIL)
# ─────────────────────────────────────────


def _make_icon_image() -> Image.Image:
    """Load shield.png from the assets folder, falling back to a drawn icon."""
    assets_path = os.path.join(BASE_DIR, "assets", "shield2.png")
    if os.path.exists(assets_path):
        return Image.open(assets_path).convert("RGBA")

    # Fallback: draw a simple shield if the file is missing
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    shield = [(32, 3), (61, 15), (61, 37), (32, 61), (3, 37), (3, 15)]
    draw.polygon(shield, fill=(28, 78, 128))
    inner = [(32, 11), (53, 21), (53, 38), (32, 54), (11, 38), (11, 21)]
    draw.polygon(inner, fill=(52, 152, 219))
    draw.rectangle([25, 33, 39, 44], fill="white")
    draw.arc([26, 24, 38, 36], start=0, end=180, fill="white", width=3)
    return img


# ─────────────────────────────────────────
#  WINDOW  (show / hide)
# ─────────────────────────────────────────

def _show_window():
    """Bring the settings window to the front (safe to call from any thread)."""
    if _root:
        _root.after(0, lambda: (
            _root.deiconify(),
            _root.lift(),
            _root.focus_force(),
        ))


def _hide_window():
    """Hide the window to the tray without stopping the main loop."""
    if _root:
        _root.withdraw()


def _quit_app():
    """Fully stop the app — tray icon, tkinter, and the whole process."""
    if _tray_icon:
        _tray_icon.stop()
    if _root:
        _root.after(0, _root.destroy)


def _restart_app():
    """Restart the application by re-executing the current process."""
    if _tray_icon:
        _tray_icon.stop()
    if _root:
        _root.after(0, _root.destroy)
    os.execv(sys.executable, [sys.executable] + sys.argv)


# ─────────────────────────────────────────
#  SETTINGS WINDOW  (built once, reused)
# ─────────────────────────────────────────

def _build_window():
    """
    Build and return the Tk root window (does NOT call mainloop).
    The window is shown immediately; closing it hides to tray.
    """
    global _root

    root = tk.Tk()
    root.title("PrivacyGuard — Settings")
    root.resizable(False, False)
    _root = root
    
    icon = tk.PhotoImage(file="./assets/shield2.png")
    root.iconphoto(True, icon)

    # ── Header bar ──────────────────────────────────────────────────────────
    header = tk.Frame(root, bg="#1c4e80", pady=14)
    header.pack(fill="x")
    tk.Label(
        header, text="🛡  PrivacyGuard",
        font=("Segoe UI", 15, "bold"), bg="#1c4e80", fg="white"
    ).pack()
    tk.Label(
        header, text="Running in background  •  Monitoring your files",
        font=("Segoe UI", 9), bg="#1c4e80", fg="#aed6f1"
    ).pack()

    # ── Body ────────────────────────────────────────────────────────────────
    body = tk.Frame(root, padx=22, pady=16)
    body.pack(fill="both")
    body.columnconfigure(0, weight=1)

    # Status indicator
    status_frame = tk.Frame(body, bg="#eafaf1", relief="flat", bd=1)
    status_frame.grid(row=0, column=0, sticky="ew", pady=(0, 14))
    tk.Label(
        status_frame, text="● Scanner is active",
        font=("Segoe UI", 9), fg="#1e8449", bg="#eafaf1", padx=8, pady=5
    ).pack(anchor="w")

    # ── Watch Folders ───────────────────────────────────────────────────────
    tk.Label(
        body, text="Watch Folders",
        font=("Segoe UI", 10, "bold"), anchor="w"
    ).grid(row=1, column=0, sticky="w", pady=(0, 3))
    tk.Label(
        body, text="Add one or more folders to monitor for sensitive files.",
        font=("Segoe UI", 8), fg="#7f8c8d", anchor="w"
    ).grid(row=2, column=0, sticky="w", pady=(0, 5))

    folders_frame = tk.Frame(body)
    folders_frame.grid(row=3, column=0, sticky="ew", pady=(0, 14))

    listbox_frame = tk.Frame(folders_frame)
    listbox_frame.pack(fill="x")

    scrollbar = tk.Scrollbar(listbox_frame, orient="vertical")
    folders_listbox = tk.Listbox(
        listbox_frame, height=4, width=50,
        yscrollcommand=scrollbar.set, selectmode="single",
        font=("Segoe UI", 9)
    )
    scrollbar.config(command=folders_listbox.yview)
    folders_listbox.pack(side="left", fill="x", expand=True)
    scrollbar.pack(side="left", fill="y")

    for f in config.get_watch_folders():
        folders_listbox.insert(tk.END, f)

    folder_btn_frame = tk.Frame(folders_frame)
    folder_btn_frame.pack(anchor="w", pady=(6, 0))

    def add_folder():
        path = filedialog.askdirectory(title="Select folder to watch")
        if path and path not in folders_listbox.get(0, tk.END):
            folders_listbox.insert(tk.END, path)

    def remove_folder():
        sel = folders_listbox.curselection()
        if sel:
            folders_listbox.delete(sel[0])

    tk.Button(
        folder_btn_frame, text="＋ Add Folder",
        command=add_folder, padx=8, pady=3, font=("Segoe UI", 9)
    ).pack(side="left", padx=(0, 6))
    tk.Button(
        folder_btn_frame, text="✕ Remove Selected",
        command=remove_folder, padx=8, pady=3, font=("Segoe UI", 9)
    ).pack(side="left")

    # ── Existing Archive ─────────────────────────────────────────────────────
    tk.Label(
        body, text="Existing Encrypted Archive  (optional)",
        font=("Segoe UI", 10, "bold"), anchor="w"
    ).grid(row=4, column=0, sticky="w", pady=(0, 2))
    tk.Label(
        body,
        text="When set, you can add sensitive files directly to this ZIP when a scan alert appears.",
        font=("Segoe UI", 8), fg="#7f8c8d", anchor="w", wraplength=400, justify="left"
    ).grid(row=5, column=0, sticky="w", pady=(0, 5))

    archive_var = tk.StringVar(value=config.get("archive_path"))
    archive_frame = tk.Frame(body)
    archive_frame.grid(row=6, column=0, sticky="ew", pady=(0, 10))

    tk.Entry(archive_frame, textvariable=archive_var, width=32).pack(side="left", padx=(0, 6))
    tk.Button(
        archive_frame, text="Browse…",
        command=lambda: archive_var.set(
            filedialog.askopenfilename(
                title="Select existing encrypted ZIP",
                filetypes=[("ZIP archives", "*.zip"), ("All files", "*.*")]
            ) or archive_var.get()
        )
    ).pack(side="left", padx=(0, 4))
    tk.Button(
        archive_frame, text="Clear",
        command=lambda: archive_var.set("")
    ).pack(side="left")

    # ── Archive Password ──────────────────────────────────────────────────────
    tk.Label(
        body, text="Archive Password",
        font=("Segoe UI", 10, "bold"), anchor="w"
    ).grid(row=7, column=0, sticky="w", pady=(0, 2))
    tk.Label(
        body, text="Held in memory only — never written to disk. Re-enter after restarting the app.",
        font=("Segoe UI", 8), fg="#7f8c8d", anchor="w", wraplength=400, justify="left"
    ).grid(row=8, column=0, sticky="w", pady=(0, 5))

    pw_var = tk.StringVar(value=config.get_archive_password())
    tk.Entry(body, textvariable=pw_var, show="*", width=30).grid(
        row=9, column=0, sticky="w", pady=(0, 18)
    )

    # ── Action buttons ────────────────────────────────────────────────────────
    btn_frame = tk.Frame(body)
    btn_frame.grid(row=10, column=0, sticky="e")

    def on_save():
        new_folders = list(folders_listbox.get(0, tk.END))
        folders_changed = new_folders != config.get_watch_folders()

        config.set("watch_folders", new_folders)
        config.set("archive_path", archive_var.get())
        config.set_archive_password(pw_var.get())
        config.save()

        if folders_changed:
            should_restart = messagebox.askyesno(
                "Restart Required",
                "Watch folders have changed.\n\nRestart PrivacyGuard now to apply the new folders?",
                parent=root
            )
            if should_restart:
                _restart_app()
                return
        else:
            saved_label.config(text="✓ Settings saved.")
            root.after(2500, lambda: saved_label.config(text=""))

    tk.Button(
        btn_frame, text="Hide to Tray", command=_hide_window,
        padx=10, pady=4, font=("Segoe UI", 9)
    ).pack(side="left", padx=(0, 8))
    tk.Button(
        btn_frame, text="Save Settings", command=on_save,
        bg="#307bc5", fg="white", padx=14, pady=4, font=("Segoe UI", 9, "bold")
    ).pack(side="left")

    saved_label = tk.Label(body, text="", fg="#1e8449", font=("Segoe UI", 9))
    saved_label.grid(row=11, column=0, sticky="w", pady=(4, 0))

    # Closing the window hides it to the tray instead of quitting
    root.protocol("WM_DELETE_WINDOW", _hide_window)

    return root


# ─────────────────────────────────────────
#  SYSTEM TRAY
# ─────────────────────────────────────────

def _start_tray():
    """Run the pystray icon (blocking — call in a daemon thread)."""
    global _tray_icon

    menu = pystray.Menu(
        pystray.MenuItem("Open Settings", lambda icon, item: _show_window(), default=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Restart", lambda icon, item: _restart_app()),
        pystray.MenuItem("Quit PrivacyGuard", lambda icon, item: _quit_app()),
    )
    _tray_icon = pystray.Icon(
        name="PrivacyGuard",
        icon=_make_icon_image(),
        title="PrivacyGuard — active",
        menu=menu,
    )
    _tray_icon.run()


# ─────────────────────────────────────────
#  PUBLIC ENTRY POINT
# ─────────────────────────────────────────

def launch():
    """
    Build the settings window, start the tray in a daemon thread,
    then hand control to tkinter's main loop (blocks until Quit).
    Call this from the main thread.
    """
    root = _build_window()

    # Tray runs in its own daemon thread so it doesn't block tkinter
    threading.Thread(target=_start_tray, daemon=True).start()

    root.mainloop()
