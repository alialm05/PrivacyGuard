"""
ui.py
Handles all tkinter popup UI for the Privacy Scanner.
"""

from logging import root
import os
import threading
import tkinter as tk
from tkinter import messagebox

import config
from zipper import encrypt_to_zip, add_to_existing_zip, delete_file


def _lift(root):
    """Move root off-screen and show it so messageboxes appear on top without a visible blank window."""
    root.geometry("1x1+-32000+-32000")
    root.deiconify()
    root.attributes('-topmost', True)
    #root.lift()
    #root.focus_force()
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
        
        filename = os.path.basename(filepath)

        # Build summary message
        lines = [f"Sensitive data detected in:\n{filename}\n"]
        if is_id:
            lines.append("- Likely ID document (driver's license or passport)")
        for label, sample, count in findings:
            lines.append(f"- {label} ({count} occurrence{'s' if count > 1 else ''})")
        message = "\n".join(lines)

        archive_path = config.get("archive_path")
        archive_password = config.get_archive_password()

        if archive_path and archive_password:
            # Offer 3 choices: add to existing archive, create new zip, or skip
            print(f"\n[Popup] Existing archive configured: {os.path.basename(archive_path)}")
            _show_action_dialog(root, filepath, message, archive_path, archive_password)

        else:
            print(f"\n[Popup] No archive configured. Prompting to create new encrypted ZIP.")
            # Fallback: simple yes/no for creating a new encrypted ZIP
            lines.append("\nWould you like to encrypt this file into a password-protected ZIP?")
            _lift(root)
            encrypt = messagebox.askyesno(
                title="Privacy Scanner - Sensitive File Detected",
                message="\n".join(lines),
                parent=root
            )
            root.withdraw()
            if encrypt:
                _show_password_window(root, filepath)

        root.destroy()

    threading.Thread(target=run_popup, daemon=True).start()


def _show_action_dialog(root, filepath, summary_message, archive_path, archive_password):
    """
    Show a custom 3-button dialog when an existing archive is configured:
      [Add to Archive]  [Create New ZIP]  [Skip]
    """
    dlg = tk.Toplevel(root)
    dlg.title("Privacy Scanner — Sensitive File Detected")
    dlg.resizable(False, False)
    dlg.attributes('-topmost', True)
    dlg.grab_set()

    tk.Label(
        dlg, text=summary_message,
        justify="left", padx=20, pady=14, anchor="w"
    ).pack(fill="x")

    tk.Frame(dlg, height=1, bg="#dcdde1").pack(fill="x", padx=0)

    tk.Label(
        dlg,
        text=f"Archive: {os.path.basename(archive_path)}",
        font=("Segoe UI", 8), fg="#7f8c8d", padx=20, pady=4
    ).pack(anchor="w")

    btn_frame = tk.Frame(dlg, padx=16, pady=12)
    btn_frame.pack()

    choice = tk.StringVar(value="skip")

    def pick(value):
        choice.set(value)
        dlg.destroy()

    tk.Button(
        btn_frame, text="Add to Existing Archive",
        bg="#2980b9", fg="white", padx=10, pady=5, font=("Segoe UI", 9, "bold"),
        command=lambda: pick("archive")
    ).pack(side="left", padx=(0, 8))

    tk.Button(
        btn_frame, text="Create New ZIP",
        bg="#27ae60", fg="white", padx=10, pady=5,
        command=lambda: pick("new_zip")
    ).pack(side="left", padx=(0, 8))

    tk.Button(
        btn_frame, text="Skip",
        padx=10, pady=5,
        command=lambda: pick("skip")
    ).pack(side="left")

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
    password_window.grab_set()  # Make it modal
    password_window.attributes('-topmost', True)  # Appear above all other windows

    password_window.focus_force()

    tk.Label(password_window, text="Enter a password for the encrypted ZIP:",
             padx=20, pady=10).pack()

    password_entry = tk.Entry(password_window, show="*", width=30)
    password_entry.pack(padx=20)
    password_window.after(100, lambda: (password_window.lift(), password_window.focus_force(), password_entry.focus_set()))

    tk.Label(password_window, text="Confirm password:", padx=20, pady=5).pack()
    confirm_entry = tk.Entry(password_window, show="*", width=30)
    confirm_entry.pack(padx=20)

    error_label = tk.Label(password_window, text="", fg="red")
    error_label.pack(pady=5)

    def on_confirm():
        password = password_entry.get()
        confirm = confirm_entry.get()

        print("password enered: ", password)
        print("confirmed password enered: ", confirm)
        

        if len(password) < 6:
            error_label.config(text="Password must be at least 6 characters.")
            return
        if password != confirm:
            error_label.config(text="Passwords do not match.")
            return

        password_window.destroy()
        _handle_encryption(root, filepath, password)

    tk.Button(
        password_window, text="Encrypt", command=on_confirm,
        bg="#307bc5", fg="white", padx=14, pady=4, font=("Segoe UI", 9, "bold")).pack(pady=10)

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