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
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageDraw, ImageTk
import pystray

import config
from ui import _apply_styles
from zipper import create_empty_zip

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Module-level references ────────────────────────────────────────────────────
_root: tk.Tk | None = None      # the one persistent Tk root
_tray_icon: pystray.Icon | None = None


# ─────────────────────────────────────────
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
#  GUARDED FOLDER DIALOGS
# ─────────────────────────────────────────

def _show_create_guarded_folder(root, on_confirm_cb):
    """Dialog: choose parent directory + archive name + password → calls on_confirm_cb(path, pw)."""
    win = tk.Toplevel(root)
    win.title("Create New Guarded Folder")
    win.resizable(False, False)
    win.grab_set()
    win.configure(bg="#f5f6f8")
    win.columnconfigure(1, weight=1)

    pad = {"padx": 12, "pady": 6}

    ttk.Label(win, text="Parent Directory:").grid(row=0, column=0, sticky="w", **pad)
    dir_var = tk.StringVar(master=win, value=os.path.expanduser("~"))
    ttk.Entry(win, textvariable=dir_var, width=34).grid(row=0, column=1, sticky="ew", padx=(0, 4), pady=6)
    ttk.Button(win, text="Browse…", command=lambda: dir_var.set(
        filedialog.askdirectory(title="Choose parent directory", parent=win) or dir_var.get()
    )).grid(row=0, column=2, padx=(0, 12), pady=6)

    ttk.Label(win, text="Archive Name:").grid(row=1, column=0, sticky="w", **pad)
    name_var = tk.StringVar(master=win, value="guarded")
    ttk.Entry(win, textvariable=name_var, width=24).grid(row=1, column=1, sticky="w", padx=(0, 4), pady=6)
    ttk.Label(win, text=".zip", style="Sub.TLabel").grid(row=1, column=2, sticky="w", padx=(0, 12), pady=6)

    ttk.Label(win, text="Password:").grid(row=2, column=0, sticky="w", **pad)
    pw_var = tk.StringVar(master=win)
    ttk.Entry(win, textvariable=pw_var, show="*", width=28).grid(row=2, column=1, columnspan=2, sticky="ew", padx=(0, 12), pady=6)

    ttk.Label(win, text="Confirm Password:").grid(row=3, column=0, sticky="w", **pad)
    pw2_var = tk.StringVar(master=win)
    ttk.Entry(win, textvariable=pw2_var, show="*", width=28).grid(row=3, column=1, columnspan=2, sticky="ew", padx=(0, 12), pady=6)

    err_label = ttk.Label(win, text="", foreground="red", font=("Segoe UI", 8))
    err_label.grid(row=4, column=0, columnspan=3, sticky="w", padx=12)

    def on_confirm():
        parent = dir_var.get().strip()
        name   = name_var.get().strip()
        pw     = pw_var.get()
        pw2    = pw2_var.get()
        if not parent or not os.path.isdir(parent):
            err_label.config(text="Please select a valid parent directory.")
            return
        if not name:
            err_label.config(text="Please enter an archive name.")
            return
        if not pw:
            err_label.config(text="Password cannot be empty.")
            return
        if pw != pw2:
            err_label.config(text="Passwords do not match.")
            return
        if not name.endswith(".zip"):
            name = name + ".zip"
        full_path = os.path.join(parent, name)
        if not create_empty_zip(full_path, pw):
            err_label.config(text=f"Could not create archive at:\n{full_path}")
            return
        on_confirm_cb(full_path, pw)
        win.destroy()

    ttk.Separator(win, orient="horizontal").grid(
        row=5, column=0, columnspan=3, sticky="ew", padx=12, pady=(8, 0))
    btn_row = ttk.Frame(win)
    btn_row.grid(row=6, column=0, columnspan=3, sticky="e", padx=12, pady=(6, 12))
    ttk.Button(btn_row, text="Cancel", command=win.destroy).pack(side="left", padx=(0, 8))
    ttk.Button(btn_row, text="Confirm", command=on_confirm,
               style="Primary.TButton").pack(side="left")

    win.after(80, lambda: (win.lift(), win.focus_force()))


def _show_select_guarded_folder(root, current_path, current_pw, on_confirm_cb):
    """Dialog: browse for existing ZIP + enter password → calls on_confirm_cb(path, pw)."""
    win = tk.Toplevel(root)
    win.title("Select Existing Guarded Folder")
    win.resizable(False, False)
    win.grab_set()
    win.configure(bg="#f5f6f8")
    win.columnconfigure(1, weight=1)

    pad = {"padx": 12, "pady": 6}

    ttk.Label(win, text="Archive File:").grid(row=0, column=0, sticky="w", **pad)
    zip_var = tk.StringVar(master=win, value=current_path or "")
    ttk.Entry(win, textvariable=zip_var, width=34).grid(row=0, column=1, sticky="ew", padx=(0, 4), pady=6)
    ttk.Button(win, text="Browse…", command=lambda: zip_var.set(
        filedialog.askopenfilename(
            title="Select encrypted ZIP",
            filetypes=[("ZIP archives", "*.zip"), ("All files", "*.*")],
            parent=win
        ) or zip_var.get()
    )).grid(row=0, column=2, padx=(0, 12), pady=6)

    ttk.Label(win, text="Password:").grid(row=1, column=0, sticky="w", **pad)
    pw_var = tk.StringVar(master=win, value=current_pw or "")
    ttk.Entry(win, textvariable=pw_var, show="*", width=28).grid(
        row=1, column=1, columnspan=2, sticky="ew", padx=(0, 12), pady=6)

    err_label = ttk.Label(win, text="", foreground="red", font=("Segoe UI", 8))
    err_label.grid(row=2, column=0, columnspan=3, sticky="w", padx=12)

    def on_confirm():
        zp = zip_var.get().strip()
        pw = pw_var.get()
        if not zp:
            err_label.config(text="Please select a ZIP file.")
            return
        if not pw:
            err_label.config(text="Password cannot be empty.")
            return
        on_confirm_cb(zp, pw)
        win.destroy()

    ttk.Separator(win, orient="horizontal").grid(
        row=3, column=0, columnspan=3, sticky="ew", padx=12, pady=(8, 0))
    btn_row = ttk.Frame(win)
    btn_row.grid(row=4, column=0, columnspan=3, sticky="e", padx=12, pady=(6, 12))
    ttk.Button(btn_row, text="Cancel", command=win.destroy).pack(side="left", padx=(0, 8))
    ttk.Button(btn_row, text="Confirm", command=on_confirm,
               style="Primary.TButton").pack(side="left")

    win.after(80, lambda: (win.lift(), win.focus_force()))


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

    BG = _apply_styles(root)
    root.configure(bg=BG)

    # Pre-render section header icons from assets (refs kept on root to prevent GC)
    def _load_icon(name):
        path = os.path.join(BASE_DIR, "assets", name)
        if os.path.exists(path):
            return ImageTk.PhotoImage(Image.open(path).convert("RGBA").resize((16, 16), Image.LANCZOS))
        return None
    _folder_photo = _load_icon("folder.png")
    _lock_photo   = _load_icon("lockicon.png")
    root._icon_refs = [_folder_photo, _lock_photo]  # type: ignore

    # ── Header bar (plain tk so we can colour it) ────────────────────────────
    header = tk.Frame(root, bg="#2061a1", pady=14)
    header.pack(fill="x")
    tk.Label(
        header, text="🛡  PrivacyGuard",
        font=("Segoe UI", 15, "bold"), bg="#2061a1", fg="white"
    ).pack()
    tk.Label(
        header, text="Running in background  •  Monitoring your files",
        font=("Segoe UI", 9), bg="#2061a1", fg="#aed6f1"
    ).pack()

    # ── Body ────────────────────────────────────────────────────────────────
    body = ttk.Frame(root, padding=(22, 16))
    body.pack(fill="both")
    body.columnconfigure(0, weight=1)

    # Status pill
    status_frame = tk.Frame(body, bg="#dcfce7", padx=10, pady=5)
    status_frame.grid(row=0, column=0, sticky="ew", pady=(0, 16))
    tk.Label(
        status_frame, text="● Scanner is active",
        font=("Segoe UI", 9), fg="#15803d", bg="#dcfce7"
    ).pack(anchor="w")

    # ── Watch Folders ───────────────────────────────────────────────────────
    wf_header = ttk.Frame(body)
    wf_header.grid(row=1, column=0, sticky="w", pady=(0, 2))
    if _folder_photo:
        tk.Label(wf_header, image=_folder_photo, bg=BG, bd=0).pack(side="left", padx=(0, 6))
    ttk.Label(wf_header, text="Watch Folders", style="H2.TLabel").pack(side="left")
    ttk.Label(body, text="Add one or more folders to monitor for sensitive files.",
              style="Sub.TLabel").grid(row=2, column=0, sticky="w", pady=(0, 6))

    folders_frame = ttk.Frame(body)
    folders_frame.grid(row=3, column=0, sticky="ew", pady=(0, 14))

    listbox_frame = ttk.Frame(folders_frame)
    listbox_frame.pack(fill="x")

    scrollbar = ttk.Scrollbar(listbox_frame, orient="vertical")
    folders_listbox = tk.Listbox(
        listbox_frame, height=4, width=50,
        yscrollcommand=scrollbar.set, selectmode="single",
        font=("Segoe UI", 9), relief="flat", bd=0,
        bg="#ffffff", fg="#1a1a2e",
        selectbackground="#dbeafe", selectforeground="#1e3a8a",
        highlightbackground="#d1d5db", highlightthickness=1,
        activestyle="none"
    )
    scrollbar.config(command=folders_listbox.yview)
    folders_listbox.pack(side="left", fill="x", expand=True)
    scrollbar.pack(side="left", fill="y")

    for f in config.get_watch_folders():
        folders_listbox.insert(tk.END, f)

    folder_btn_frame = ttk.Frame(folders_frame)
    folder_btn_frame.pack(anchor="w", pady=(6, 0))

    def add_folder():
        path = filedialog.askdirectory(title="Select folder to watch")
        if path and path not in folders_listbox.get(0, tk.END):
            folders_listbox.insert(tk.END, path)

    def remove_folder():
        sel = folders_listbox.curselection()
        if sel:
            folders_listbox.delete(sel[0])

    ttk.Button(folder_btn_frame, text="＋ Add Folder",
               command=add_folder).pack(side="left", padx=(0, 6))
    ttk.Button(folder_btn_frame, text="✕ Remove Selected",
               command=remove_folder, style="Danger.TButton").pack(side="left")

    # ── Separator ────────────────────────────────────────────────────────────
    ttk.Separator(body, orient="horizontal").grid(
        row=4, column=0, sticky="ew", pady=(0, 0))

    # ── Guarded Folder ──────────────────────────────────────────────────────
    gf_section = ttk.Frame(body)
    gf_section.grid(row=5, column=0, sticky="ew", pady=(20, 25))
    gf_section.columnconfigure(0, weight=1)

    gf_header = ttk.Frame(gf_section)
    gf_header.pack(fill="x")
    if _lock_photo:
        tk.Label(gf_header, image=_lock_photo, bg=BG, bd=0).pack(side="left", padx=(0, 6))
    ttk.Label(gf_header, text="Guarded Folder", style="H2.TLabel").pack(side="left")
    ttk.Label(
        gf_section,
        text="Sensitive files can be encrypted directly into a password-protected ZIP archive.",
        style="Sub.TLabel", wraplength=380, justify="left"
    ).pack(fill="x", pady=(2, 10))

    # Local state — updated via nonlocal in closures below
    _guarded_path = config.get("archive_path") or ""
    _guarded_pw   = config.get_archive_password() or ""

    current_name = os.path.basename(_guarded_path) if _guarded_path else "None configured"
    guarded_label = ttk.Label(gf_section, text=f"Current: {current_name}", style="Meta.TLabel")
    guarded_label.pack(fill="x", pady=(0, 10))

    def _refresh_guarded_label():
        name = os.path.basename(_guarded_path) if _guarded_path else "None configured"
        guarded_label.config(text=f"Current: {name}")
        if _guarded_path:
            pw_frame.pack(fill="x", pady=(8, 0))
        else:
            pw_frame.pack_forget()

    def _set_guarded(path, pw):
        nonlocal _guarded_path, _guarded_pw
        _guarded_path = path
        _guarded_pw   = pw
        pw_var.set(pw)
        _refresh_guarded_label()

    def open_create_guarded():
        _show_create_guarded_folder(root, _set_guarded)

    def open_select_guarded():
        _show_select_guarded_folder(root, _guarded_path, _guarded_pw, _set_guarded)

    def clear_guarded():
        nonlocal _guarded_path, _guarded_pw
        _guarded_path = ""
        _guarded_pw   = ""
        pw_var.set("")
        _refresh_guarded_label()

    gf_btn_frame = ttk.Frame(gf_section)
    gf_btn_frame.pack(anchor="w")

    ttk.Button(gf_btn_frame, text="+ Create New",
               command=open_create_guarded).pack(side="left", padx=(0, 6))
    ttk.Button(gf_btn_frame, text="Select Existing",
               command=open_select_guarded).pack(side="left", padx=(0, 6))
    ttk.Button(gf_btn_frame, text="✕ Clear",
               command=clear_guarded, style="Danger.TButton").pack(side="left")

    # Inline password entry — shown only when a guarded folder is configured
    pw_frame = ttk.Frame(gf_section)
    pw_var = tk.StringVar(master=root, value=_guarded_pw)
    ttk.Label(
        pw_frame,
        text="Enter the password for this ZIP so files can be sent here automatically. This password is saved only in memory",
        style="Sub.TLabel", wraplength=380, justify="left"
    ).pack(anchor="w", pady=(0, 4))
    ttk.Entry(pw_frame, textvariable=pw_var, show="*", width=32).pack(anchor="w")
    if _guarded_path:
        pw_frame.pack(fill="x", pady=(8, 0))

    # ── Separator ────────────────────────────────────────────────────────────
    ttk.Separator(body, orient="horizontal").grid(
        row=6, column=0, sticky="ew", pady=(0, 12))

    # ── Action buttons ────────────────────────────────────────────────────────
    btn_frame = ttk.Frame(body)
    btn_frame.grid(row=7, column=0, sticky="e")

    def on_save():
        new_folders = list(folders_listbox.get(0, tk.END))
        folders_changed = new_folders != config.get_watch_folders()

        config.set("watch_folders", new_folders)
        config.set("archive_path", _guarded_path)
        print("pw_var:", pw_var.get())
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

    ttk.Button(btn_frame, text="Hide to Tray",
               command=_hide_window).pack(side="left", padx=(0, 8))
    ttk.Button(btn_frame, text="Save Settings", command=on_save,
               style="Primary.TButton").pack(side="left")

   

    saved_label = ttk.Label(body, text="", style="Success.TLabel")
    saved_label.grid(row=8, column=0, sticky="w", pady=(8, 0))

    ttk.Label(body, text="⚠  Remember to save your settings for any changes to take effect.",
              style="Sub.TLabel").grid(row=9, column=0, sticky="w", pady=(0, 0))

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
