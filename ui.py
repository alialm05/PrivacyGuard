"""
ui.py
Handles all tkinter popup UI for the Privacy Scanner.
"""

import os
import threading
import tkinter as tk
from tkinter import messagebox

from zipper import encrypt_to_zip, delete_file


def show_sensitive_popup(filepath, findings, is_id):
    """
    Show a popup when sensitive data is detected.
    Runs in its own thread so it doesn't block the file watcher.
    """
    def run_popup():
        root = tk.Tk()
        root.withdraw()  # Hide blank root window

        filename = os.path.basename(filepath)

        # Build summary message
        lines = [f"Sensitive data detected in:\n{filename}\n"]
        if is_id:
            lines.append("- Likely ID document (driver's license or passport)")
        for label, sample, count in findings:
            lines.append(f"- {label} ({count} occurrence{'s' if count > 1 else ''})")
        lines.append("\nWould you like to encrypt this file into a password-protected ZIP?")
        message = "\n".join(lines)

        # Ask yes/no
        encrypt = messagebox.askyesno(
            title="Privacy Scanner - Sensitive File Detected",
            message=message
        )

        if encrypt:
            _show_password_window(root, filepath)

        root.destroy()

    threading.Thread(target=run_popup, daemon=True).start()


def _show_password_window(root, filepath):
    """Show the password entry window and handle encryption on confirm."""
    password_window = tk.Toplevel(root)
    password_window.title("Set Encryption Password")
    password_window.resizable(False, False)
    password_window.grab_set()  # Make it modal

    tk.Label(password_window, text="Enter a password for the encrypted ZIP:",
             padx=20, pady=10).pack()

    password_var = tk.StringVar()
    password_entry = tk.Entry(password_window, textvariable=password_var,
                              show="*", width=30)
    password_entry.pack(padx=20)
    password_entry.focus()

    tk.Label(password_window, text="Confirm password:", padx=20, pady=5).pack()
    confirm_var = tk.StringVar()
    tk.Entry(password_window, textvariable=confirm_var,
             show="*", width=30).pack(padx=20)

    error_label = tk.Label(password_window, text="", fg="red")
    error_label.pack(pady=5)

    def on_confirm():
        password = password_var.get()
        confirm = confirm_var.get()

        if len(password) < 6:
            error_label.config(text="Password must be at least 6 characters.")
            return
        if password != confirm:
            error_label.config(text="Passwords do not match.")
            return

        password_window.destroy()
        _handle_encryption(filepath, password)

    tk.Button(password_window, text="Encrypt", command=on_confirm,
              bg="#2ecc71", fg="white", padx=10, pady=5).pack(pady=10)

    password_window.bind("<Return>", lambda e: on_confirm())
    root.wait_window(password_window)


def _handle_encryption(filepath, password):
    """Run encryption and ask user whether to delete the original."""
    root = tk.Tk()
    root.withdraw()

    zip_path = encrypt_to_zip(filepath, password)

    if zip_path:
        should_delete = messagebox.askyesno(
            title="Delete Original?",
            message=f"Encrypted ZIP created successfully!\n\n"
                    f"{os.path.basename(zip_path)}\n\n"
                    f"Do you want to delete the original unencrypted file?"
        )
        if should_delete:
            success = delete_file(filepath)
            if success:
                messagebox.showinfo("Done", "Original file deleted. Only the encrypted ZIP remains.")
            else:
                messagebox.showerror("Error", "Could not delete the original file. Check console for details.")
        else:
            messagebox.showinfo("Done", "Encrypted ZIP saved. Original file kept.")
    else:
        messagebox.showerror("Error", "Encryption failed. Check the console for details.")

    root.destroy()