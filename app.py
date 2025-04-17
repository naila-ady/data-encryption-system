
import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import time
import base64
import json

# Session State Initialization
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"
if 'last_stored_time' not in st.session_state:
    st.session_state.last_stored_time = 0

def hash_passkey(passkey):
    encoded = passkey.encode()
    hashed = hashlib.sha256(encoded)
    return hashed.hexdigest()

def gen_key_from_passkey(passkey):
    encoded = passkey.encode()
    hash = hashlib.sha256(encoded).digest()
    return base64.urlsafe_b64encode(hash[:32])

def encrypt_data(text, passkey):
    plain_key = gen_key_from_passkey(passkey)
    cipher_Key = Fernet(plain_key)
    return cipher_Key.encrypt(text.encode()).decode()

def decrypt_data(encryptedtext, passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data:
            key = gen_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encryptedtext.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_stored_time = time.time()
            return None
    except Exception as e:
        st.session_state.failed_attempts += 1
        st.session_state.last_stored_time = time.time()
        return f"❌ Decryption failed: {str(e)}"

def generate_id_data():
    import uuid
    return str(uuid.uuid4())

def reset_failed_attempts():
    st.session_state.failed_attempts = 0

def change_page(page):
    st.session_state.current_page = page

# --- UI Section ---
st.set_page_config(page_title="Encryption App", layout="centered")

st.sidebar.title("🔐 Navigation")
page = st.sidebar.radio("Go to", ("Home", "Encrypt", "Decrypt"))
change_page(page)

st.title("🔐 Simple Encryption App")

if st.session_state.current_page == "Home":
    st.info("Welcome! Use the sidebar to Encrypt or Decrypt messages.")

elif st.session_state.current_page == "Encrypt":
    st.subheader("🔒 Encrypt Your Text")
    text = st.text_area("Enter text to encrypt")
    passkey = st.text_input("Enter passkey", type="password")
    if st.button("Encrypt"):
        if text and passkey:
            encrypted = encrypt_data(text, passkey)
            data_id = generate_id_data()
            st.session_state.stored_data[data_id] = encrypted
            st.success("Text encrypted successfully!")
            st.code(encrypted, language='text')
            st.write(f"🆔 Data ID: `{data_id}`")
        else:
            st.warning("Please enter both text and passkey.")

elif st.session_state.current_page == "Decrypt":
    st.subheader("🔓 Decrypt Your Text")
    encrypted_text = st.text_area("Enter encrypted text")
    passkey = st.text_input("Enter passkey", type="password")
    data_id = st.text_input("Enter data ID")
    if st.button("Decrypt"):
        if encrypted_text and passkey and data_id:
            decrypted = decrypt_data(encrypted_text, passkey, data_id)
            if decrypted:
                st.success("Text decrypted successfully!")
                st.code(decrypted, language='text')
            else:
                st.error("Decryption failed or Data ID not found.")
        else:
            st.warning("Please fill in all fields to decrypt.")

    
    

