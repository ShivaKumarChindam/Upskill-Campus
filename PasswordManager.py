import tkinter as tk
from tkinter import messagebox
import secrets
import string
from cryptography.fernet import Fernet
import sqlite3  # Use sqlite3 instead of mysql.connector
import atexit
import os

# Function to generate a strong password
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

# Function to encrypt a password
def encrypt_password(password, key):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(password.encode())

# Function to decrypt a password
def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_password).decode()

# Function to store a password in the database
def store_password(cursor, account, username, password):
    encrypted_password = encrypt_password(password, key)
    cursor.execute("INSERT INTO passwords (account, username, password) VALUES (?, ?, ?)",
                   (account, username, encrypted_password))

# Function to retrieve a password from the database
def retrieve_password(cursor, account, username):
    cursor.execute("SELECT password FROM passwords WHERE account=? AND username=?", (account, username))
    password = cursor.fetchone()
    return password[0] if password else None

# Event handler for storing a password
def store_password_handler():
    account = account_entry.get()
    username = username_entry.get()
    password = password_entry.get()

    store_password(cursor, account, username, password)
    conn.commit()
    messagebox.showinfo("Success", "Password stored successfully!")

# Event handler for retrieving a password
def retrieve_password_handler():
    account = account_entry.get()
    username = username_entry.get()

    stored_password = retrieve_password(cursor, account, username)
    if stored_password:
        decrypted_password = decrypt_password(stored_password, key)
        messagebox.showinfo("Password", f"Retrieved password for '{account}' and username '{username}': '{decrypted_password}'")
    else:
        messagebox.showerror("Error", f"No password found for '{account}' and username '{username}'")

# Event handler for generating a strong password
def generate_password_handler():
    password = generate_password()
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

# Function to load encryption key from a file
def load_key():
    key_file = "key.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        return key

# Function to save encryption key to a file
def save_key():
    key_file = "key.key"
    with open(key_file, "wb") as f:
        f.write(key)

# Load the encryption key
key = load_key()

# Connect to SQLite
conn = sqlite3.connect("password_manager.db")
cursor = conn.cursor()

# Create the database and table if they don't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
             (id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT, username TEXT, password TEXT)''')

# Register the save_key function to be called when the program exits
atexit.register(save_key)

# Create the main window
window = tk.Tk()
window.title("Password Manager")

# Create and place labels and entry fields
tk.Label(window, text="Account:").place(x=100,y=700)
account_entry = tk.Entry(window)
account_entry.place(x=450,y=700)

tk.Label(window, text="Username:").place(x=100,y=800)
username_entry = tk.Entry(window)
username_entry.place(x=450,y=800)

tk.Label(window, text="Password:").place(x=100,y=900)
password_entry = tk.Entry(window)
password_entry.place(x=450,y=900)

# Create buttons for actions
store_button = tk.Button(window, text="Store Password", command=store_password_handler)
store_button.place(x=100,y=1000, height=100, width=875)

retrieve_button = tk.Button(window, text="Retrieve Password", command=retrieve_password_handler)
retrieve_button.place(x=100,y=1125, height=100, width=875)

generate_button = tk.Button(window, text="Generate Password", command=generate_password_handler)
generate_button.place(x=100,y=1250, height=100, width=875)

# Run the main event loop
window.mainloop()

# Close the cursor and connection to SQLite
cursor.close()
conn.close()
