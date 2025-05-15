import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Constants
DATA_FILE = "Secure_data.json"
SALT = b"Secure_salt_value"
LOCKOUT_DURATION = 60

# Session State Initialization
if "authenticate_user" not in st.session_state:
    st.session_state.authenticate_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Load Data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as r:
            return json.load(r)
    return {}

# Save Data
def save_data(data):
    with open(DATA_FILE, "w") as w:
        json.dump(data, w)

# Generate Encryption Key
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

# Hash Password
def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# Encrypt Text
def encrypted_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

# Decrypt Text
def decrypt_text(encrypt_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None

# Load stored data
stored_data = load_data()

# UI Navigation
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("📁 Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Data Encryption System")
    st.markdown("Protect your sensitive data with encryption and secure access control. 🔒")

elif choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ User Already Exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User Registered Successfully!")
        else:
            st.error("❗ Both fields are required!")

elif choice == "Login":
    st.subheader("🔐 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticate_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🔒 Too many failed attempts. Locked for 60 seconds.")
                st.stop()

elif choice == "Store Data":
    if st.session_state.authenticate_user is None:
        st.warning("🚫 Please login first!")
    else:
        st.subheader("💾 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption Key (Passphrase)", type="password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypted_text(data, passkey)
                stored_data[st.session_state.authenticate_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully!")
            else:
                st.error("❗ All fields are required!")

elif choice == "Retrieve Data":
    if st.session_state.authenticate_user is None:
        st.warning("🚫 Please login first!")
    else:
        st.subheader("📂 Retrieve Encrypted Data")
        user_data = stored_data.get(st.session_state.authenticate_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No encrypted data found.")
        else:
            st.write("🔐 Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("Paste Encrypted Text to Decrypt")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"🔓 Decrypted Text: {result}")
                else:
                    st.error("❌ Incorrect passkey or corrupted data.")
