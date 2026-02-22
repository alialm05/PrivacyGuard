"""
ui.py
Handles all tkinter popup UI for the Privacy Scanner.
"""

from logging import root
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import config
from zipper import encrypt_to_zip, add_to_existing_zip, delete_file


def _apply_styles(root: tk.Tk):
    """Configure ttk styles for a clean light-mode look."""
    style = ttk.Style(root)
    style.theme_use("clam")

    BG        = "#f5f6f8"
    FG        = "#1a1a2e"
    ACCENT    = "#2563eb"
    ACCENT_HV = "#1d4ed8"
    BORDER    = "#d1d5db"
    ENTRY_BG  = "#ffffff"

    style.configure(".", background=BG, foreground=FG,
                    font=("Segoe UI", 9), bordercolor=BORDER)

    # Frames / body
    style.configure("TFrame", background=BG)
    style.configure("Card.TFrame", background=BG, relief="flat")

    # Labels
    style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 9))
    style.configure("H2.TLabel", font=("Segoe UI", 10, "bold"), foreground=FG)
    style.configure("Sub.TLabel", font=("Segoe UI", 8), foreground="#6b7280")
    style.configure("Meta.TLabel", font=("Segoe UI", 9), foreground="#555555")
    style.configure("Success.TLabel", font=("Segoe UI", 9), foreground="#16a34a")
    style.configure("Status.TLabel", font=("Segoe UI", 9),
                    foreground="#15803d", background="#dcfce7")

    # Entries
    style.configure("TEntry", fieldbackground=ENTRY_BG, bordercolor=BORDER,
                    lightcolor=BORDER, darkcolor=BORDER, insertcolor=FG)
    style.map("TEntry", bordercolor=[("focus", ACCENT), ("!focus", BORDER)])

    # Default button
    style.configure("TButton", padding=(8, 4), relief="flat",
                    background="#e5e7eb", foreground=FG, bordercolor=BORDER,
                    focusthickness=0, focuscolor="")
    style.map("TButton",
              background=[("active", "#d1d5db"), ("pressed", "#9ca3af")],
              relief=[("pressed", "flat")])

    # Primary (blue) button
    style.configure("Primary.TButton", padding=(12, 5), background=ACCENT,
                    foreground="white", font=("Segoe UI", 9, "bold"),
                    bordercolor=ACCENT, focusthickness=0, focuscolor="")
    style.map("Primary.TButton",
              background=[("active", ACCENT_HV), ("pressed", "#1e40af")],
              foreground=[("active", "white")])

    # Danger / clear button
    style.configure("Danger.TButton", padding=(8, 4), background="#fee2e2",
                    foreground="#b91c1c", bordercolor="#fca5a5",
                    focusthickness=0, focuscolor="")
    style.map("Danger.TButton",
              background=[("active", "#fecaca"), ("pressed", "#fca5a5")])

    # Scrollbar
    style.configure("TScrollbar", background=BORDER, troughcolor=BG,
                    bordercolor=BG, arrowcolor="#9ca3af", relief="flat")

    # Separator
    style.configure("TSeparator", background=BORDER)

    return BG


def _lift(root):
    """Move root off-screen and show it so messageboxes appear on top without a visible blank window."""
    root.geometry("1x1+-32000+-32000")
    root.deiconify()
    root.attributes('-topmost', True)
    root.update()


def show_sensitive_popup(filepath, findings, is_id):
    """
    Show a popup when sensitive data is detected.
    Runs in its own thread so it doesn't block the file watcher.
    """
    def run_popup():
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        _apply_styles(root)

        filename = os.path.basename(filepath)

        lines = [f"Sensitive data detected in:\n{filename}\n"]
        if is_id:
            lines.append("- Likely ID document (driver's license or passport)")
        for label, sample, count in findings:
            lines.append(f"- {label} ({count} occurrence{'s' if count > 1 else ''})")
        message = "\n".join(lines)

        archive_path = config.get("archive_path")
        archive_password = config.get_archive_password()

        if archive_path and archive_password:
            print(f"\n[Popup] Existing archive configured: {os.path.basename(archive_path)}")
            _show_action_dialog(root, filepath, message, archive_path, archive_password)
        else:
            print(f"\n[Popup] No archive configured. Showing action dialog.")
            _show_no_archive_dialog(root, filepath, message)

        root.destroy()

    threading.Thread(target=run_popup, daemon=True).start()


# ─────────────────────────────────────────
#  DIALOGS
# ─────────────────────────────────────────

def _show_no_archive_dialog(root, filepath, summary_message):
    """
    3-button dialog when no archive is pre-configured:
      [Add to Existing Archive]  [Create New ZIP]  [Skip]
    """
    dlg = tk.Toplevel(root)
    dlg.title("Privacy Scanner — Sensitive File Detected")
    dlg.resizable(False, False)
    dlg.attributes('-topmost', True)
    dlg.grab_set()
    dlg.configure(bg="#f5f6f8")

    ttk.Label(dlg, text=summary_message, justify="left",
              wraplength=380).pack(fill="x", padx=20, pady=(14, 10))

    ttk.Separator(dlg, orient="horizontal").pack(fill="x")

    btn_frame = ttk.Frame(dlg)
    btn_frame.pack(padx=16, pady=12)

    choice = tk.StringVar(value="skip")

    def pick(value):
        choice.set(value)
        dlg.destroy()

    ttk.Button(btn_frame, text="Add to Existing Archive",
               style="Primary.TButton",
               command=lambda: pick("archive")).pack(side="left", padx=(0, 8))
    ttk.Button(btn_frame, text="Create New ZIP",
               style="Success.TButton",
               command=lambda: pick("new_zip")).pack(side="left", padx=(0, 8))
    ttk.Button(btn_frame, text="Skip",
               command=lambda: pick("skip")).pack(side="left")

    root.wait_window(dlg)

    if choice.get() == "archive":
        _show_select_archive_window(root, filepath)
    elif choice.get() == "new_zip":
        _show_password_window(root, filepath)


def _show_select_archive_window(root, filepath):
    """Let the user browse for an existing ZIP and enter its password, then add the file to it."""
    win = tk.Toplevel(root)
    win.title("Add to Existing Archive")
    win.resizable(False, False)
    win.grab_set()
    win.attributes('-topmost', True)
    win.configure(bg="#f5f6f8")

    body = ttk.Frame(win, padding=(20, 16))
    body.pack(fill="both")
    body.columnconfigure(1, weight=1)

    ttk.Label(body, text="Archive:").grid(
        row=0, column=0, sticky="w", padx=(0, 10), pady=(0, 8))

    zip_path_var = tk.StringVar(master=win)
    zip_entry = ttk.Entry(body, textvariable=zip_path_var, width=34)
    zip_entry.grid(row=0, column=1, sticky="ew", padx=(0, 6), pady=(0, 8))

    def browse():
        path = filedialog.askopenfilename(
            title="Select existing encrypted ZIP",
            filetypes=[("ZIP archives", "*.zip"), ("All files", "*.*")]
        )
        if path:
            zip_path_var.set(path)

    ttk.Button(body, text="Browse…", command=browse).grid(
        row=0, column=2, sticky="w", pady=(0, 8))

    ttk.Label(body, text="Password:").grid(
        row=1, column=0, sticky="w", padx=(0, 10))

    pw_entry = ttk.Entry(body, show="*")
    pw_entry.grid(row=1, column=1, columnspan=1, sticky="ew")

    error_label = ttk.Label(body, text="", foreground="red", font=("Segoe UI", 8))
    error_label.grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))

    ttk.Separator(body, orient="horizontal").grid(
        row=3, column=0, columnspan=3, sticky="ew", pady=(12, 0))

    action_row = ttk.Frame(body)
    action_row.grid(row=4, column=0, columnspan=3, sticky="e", pady=(8, 0))

    def on_confirm():
        zip_path = zip_path_var.get().strip()
        password = pw_entry.get()
        if not zip_path:
            error_label.config(text="Please select a ZIP archive.")
            return
        if not password:
            error_label.config(text="Please enter the archive password.")
            return
        win.destroy()
        success = add_to_existing_zip(filepath, zip_path, password)
        if success:
            _lift(root)
            should_delete = messagebox.askyesno(
                title="File Added to Archive",
                message=f"Added to:\n{os.path.basename(zip_path)}\n\nDelete the original unencrypted file?",
                parent=root
            )
            root.withdraw()
            if should_delete:
                delete_file(filepath)
        else:
            _lift(root)
            messagebox.showerror(
                "Error", "Could not add file to archive. Check the console for details.",
                parent=root
            )
            root.withdraw()

    ttk.Button(action_row, text="Add to Archive", command=on_confirm,
               style="Primary.TButton").pack()

    win.bind("<Return>", lambda e: on_confirm())
    win.after(100, lambda: (win.lift(), win.focus_force(),
                            pw_entry.focus_set() if zip_path_var.get() else zip_entry.focus_set()))
    root.wait_window(win)


def _show_action_dialog(root, filepath, summary_message, archive_path, archive_password):
    """
    3-button dialog when an existing archive is configured:
      [Add to Archive]  [Create New ZIP]  [Skip]
    """
    dlg = tk.Toplevel(root)
    dlg.title("Privacy Scanner — Sensitive File Detected")
    dlg.resizable(False, False)
    dlg.attributes('-topmost', True)
    dlg.grab_set()
    dlg.configure(bg="#f5f6f8")

    ttk.Label(dlg, text=summary_message, justify="left",
              wraplength=380).pack(fill="x", padx=20, pady=(14, 6))

    ttk.Separator(dlg, orient="horizontal").pack(fill="x")

    ttk.Label(dlg, text=f"Archive: {os.path.basename(archive_path)}",
              style="Sub.TLabel").pack(anchor="w", padx=20, pady=(6, 0))

    btn_frame = ttk.Frame(dlg)
    btn_frame.pack(padx=16, pady=12)

    choice = tk.StringVar(value="skip")

    def pick(value):
        choice.set(value)
        dlg.destroy()

    ttk.Button(btn_frame, text="Add to Existing Archive",
               style="Primary.TButton",
               command=lambda: pick("archive")).pack(side="left", padx=(0, 8))
    ttk.Button(btn_frame, text="Create New ZIP",
               style="Success.TButton",
               command=lambda: pick("new_zip")).pack(side="left", padx=(0, 8))
    ttk.Button(btn_frame, text="Skip",
               command=lambda: pick("skip")).pack(side="left")

    root.wait_window(dlg)

    if choice.get() == "archive":
        success = add_to_existing_zip(filepath, archive_path, archive_password)
        if success:
            _lift(root)
            should_delete = messagebox.askyesno(
                title="File Added to Archive",
                message=f"Added to:\n{os.path.basename(archive_path)}\n\nDelete the original unencrypted file?",
                parent=root
            )
            root.withdraw()
            if should_delete:
                from zipper import delete_file
                delete_file(filepath)
        else:
            _lift(root)
            messagebox.showerror(
                "Error", "Could not add file to archive. Check the console for details.",
                parent=root
            )
            root.withdraw()
    elif choice.get() == "new_zip":
        _show_password_window(root, filepath)


def _show_password_window(root, filepath):
    """Show the password entry window and handle encryption on confirm."""
    password_window = tk.Toplevel(root)
    password_window.title("Set Encryption Password")
    password_window.resizable(False, False)
    password_window.grab_set()
    password_window.attributes('-topmost', True)
    password_window.configure(bg="#f5f6f8")
    password_window.focus_force()

    body = ttk.Frame(password_window, padding=(20, 16))
    body.pack(fill="both")

    ttk.Label(body, text="Enter a password for the encrypted ZIP:").pack(anchor="w")

    password_entry = ttk.Entry(body, show="*", width=30)
    password_entry.pack(fill="x", pady=(4, 10))
    password_window.after(100, lambda: (
        password_window.lift(), password_window.focus_force(), password_entry.focus_set()
    ))

    ttk.Label(body, text="Confirm password:").pack(anchor="w")
    confirm_entry = ttk.Entry(body, show="*", width=30)
    confirm_entry.pack(fill="x", pady=(4, 0))

    error_label = ttk.Label(body, text="", foreground="red", font=("Segoe UI", 8))
    error_label.pack(anchor="w", pady=(6, 0))

    ttk.Separator(body, orient="horizontal").pack(fill="x", pady=(10, 0))

    def on_confirm():
        password = password_entry.get()
        confirm  = confirm_entry.get()
        if len(password) < 6:
            error_label.config(text="Password must be at least 6 characters.")
            return
        if password != confirm:
            error_label.config(text="Passwords do not match.")
            return
        password_window.destroy()
        _handle_encryption(root, filepath, password)

    ttk.Button(body, text="Encrypt", command=on_confirm,
               style="Primary.TButton").pack(anchor="e", pady=(10, 0))

    password_window.bind("<Return>", lambda e: on_confirm())
    root.wait_window(password_window)


def _handle_encryption(root, filepath, password):
    """Run encryption and ask user whether to delete the original."""
    zip_path = encrypt_to_zip(filepath, password)

    if zip_path:
        _lift(root)
        should_delete = messagebox.askyesno(
            title="Delete Original?",
            message=f"Encrypted ZIP created successfully!\n\n"
                    f"{os.path.basename(zip_path)}\n\n"
                    f"Do you want to delete the original unencrypted file?",
            parent=root
        )
        root.withdraw()
        if should_delete:
            success = delete_file(filepath)
            _lift(root)
            if success:
                messagebox.showinfo("Done", "Original file deleted. Only the encrypted ZIP remains.", parent=root)
            else:
                messagebox.showerror("Error", "Could not delete the original file. Check console for details.", parent=root)
            root.withdraw()
        else:
            _lift(root)
            messagebox.showinfo("Done", "Encrypted ZIP saved. Original file kept.", parent=root)
            root.withdraw()
    else:
        _lift(root)
        messagebox.showerror("Error", "Encryption failed. Check the console for details.", parent=root)
        root.withdraw()
