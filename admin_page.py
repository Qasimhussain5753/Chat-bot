import streamlit as st
from streamlit_router import StreamlitRouter
import sqlite3
import bcrypt

# Constants
DATABASE_FILE = 'user_data.db'
SESSION_KEY = 'logged_in'

# Create SQLite database and table
conn = sqlite3.connect(DATABASE_FILE)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL
    )
''')

try:
    cursor.execute('SELECT * FROM users WHERE username=?', ('admin',))
    if not cursor.fetchone():
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw('Q1w2e3r4t5'.encode(), salt)
        cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', ('admin', hashed_password.decode(), 'admin'))
    conn.commit()
finally:
    conn.close()

# Helper functions
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode(), salt.decode()

def register_user(username, password, role):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    hashed_password, salt = hash_password(password)
    cursor.execute('''
        INSERT INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
    ''', (username, hashed_password, role))

    conn.commit()
    conn.close()

def login(username, password, role):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    user_row = cursor.execute('SELECT * FROM users WHERE username=? AND role=?', (username, role)).fetchone()

    if user_row:
        hashed_password = user_row[2]
        salt = user_row[3]
        if bcrypt.checkpw(password.encode(), hashed_password.encode()):
            return True

    return False

# Login Page
def login_page(router):
    st.title("Admin Page")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
       if login(username, password, "admin"):  # Check for the "Admin" role
            st.session_state[SESSION_KEY] = True
            router.redirect(*router.build("registration_page"))
       else:
            st.error("Invalid username or password")
# Registration Page
def registration_page(router):
    st.title("Registration Page")
    new_username = st.text_input("New Username")
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    
    if st.button("Register"):
        if new_password == confirm_password:
            # Register the user
            register_user(new_username, new_password, "user")
            st.success("User Account Registration successful.")
        else:
            st.error("Passwords do not match.")


router = StreamlitRouter()
router.register(login_page, '/')
router.register(registration_page, '/registration')

router.serve()
