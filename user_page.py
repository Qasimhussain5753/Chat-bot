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

# Helper functions
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode(), salt.decode()

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
    st.title("Login Page")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if login(username, password, "user"):
            st.session_state[SESSION_KEY] = True
            router.redirect(*router.build("chat"))
        else:
            st.error("Invalid username or password")

# Chat Component
def chat(router):
    st.title("Chat Component")
    if st.button("Logout"):
        st.success("Logged out successfully.")
        st.session_state[SESSION_KEY] = False
        router.redirect(*router.build("login_page"))
        
    chat_input = st.text_input("Type a message:")
    if st.button("Send"):
        st.info(f"Message sent: {chat_input}")
    
    

router = StreamlitRouter()
router.register(login_page, '/')
router.register(chat, '/chat')

router.serve()
