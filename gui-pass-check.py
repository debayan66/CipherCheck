import tkinter as tk
from tkinter import messagebox
import re
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
import secrets  # For salt

# Your original check function
def check(password):
    strength = 0
    if len(password) >= 8: strength += 1
    if re.search(r"[A-Z]", password): strength += 1
    if re.search(r"[a-z]", password): strength += 1
    if re.search(r"[0-9]", password): strength += 1
    if re.search(r"[@$!%*?&]", password): strength += 1
    if strength == 5:
        return "STRONG"
    elif strength >= 3:
        return "MEDIUM"
    else:
        return "WEAK"

# Generate salt and hash password
def hash_password(password):
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    # Store salt + key for verification
    stored = base64.b64encode(salt + key).decode('utf-8')
    return stored

# Verify password against stored hash
def verify_password(password, stored):
    salt_key = base64.b64decode(stored.encode('utf-8'))
    salt = salt_key[:16]
    stored_key = salt_key[16:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return key == stored_key

def analyze():
    pwd = entry.get()
    confirm_pwd = confirm_entry.get()
    
    if not pwd or not confirm_pwd:
        messagebox.showerror("Error", "Please enter both passwords.")
        return
    
    if pwd != confirm_pwd:
        messagebox.showerror("Error", "Passwords do not match!")
        return
    
    result = check(pwd)
    messagebox.showinfo("Password Strength", f"Your password is: {result}")
    
    # Hash and save
    hashed = hash_password(pwd)
    with open("user_hash.txt", "w") as f:
        f.write(hashed)
    messagebox.showinfo("Success", "Password hashed and saved securely.")

def verify():
    pwd = entry.get()
    try:
        with open("user_hash.txt", "r") as f:
            stored = f.read().strip()
        if verify_password(pwd, stored):
            messagebox.showinfo("Verification", "Password matches the stored hash!")
        else:
            messagebox.showerror("Verification", "Password does not match!")
    except FileNotFoundError:
        messagebox.showerror("Error", "No stored hash found. Set a password first.")

root = tk.Tk()
root.title("Password Strength Checker with Crypto")
root.geometry("350x280")

tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=5)
entry = tk.Entry(root, show="*", width=25, font=("Arial", 12))
entry.pack()

tk.Label(root, text="Confirm Password:", font=("Arial", 12)).pack(pady=5)
confirm_entry = tk.Entry(root, show="*", width=25, font=("Arial", 12))
confirm_entry.pack()

btn = tk.Button(root, text="Check & Hash", command=analyze, font=("Arial", 12))
btn.pack(pady=10)

verify_btn = tk.Button(root, text="Verify Password", command=verify, font=("Arial", 12))
verify_btn.pack(pady=5)

root.mainloop()
