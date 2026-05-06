import secrets
import pytz
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import base64

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    send_file
)

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)
app.secret_key = "supersecretkey"

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 🔐 Generate encryption key

def generate_key(password):
    return base64.urlsafe_b64encode(password.ljust(32).encode())

# 🔑 Load RSA keys
with open("private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

with open("public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# 🛠️ Initialize Database

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        filename TEXT,
        time TEXT
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS shared_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE,
        filename TEXT,
        username TEXT,
        password_hash TEXT,
        expiry_time TEXT
    )
    ''')

    conn.commit()
    conn.close()

init_db()

# 🏠 Login Page
@app.route('/')
def login_page():
    return render_template("login.html")

# 🔐 Login Logic
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute(
        "SELECT password FROM users WHERE username=?",
        (username,)
    )

    result = c.fetchone()
    conn.close()

    if result and check_password_hash(result[0], password):
        session['user'] = username
        return redirect('/dashboard')

    return render_template(
        "login.html",
        error="❌ Invalid credentials"
    )

# 📝 Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():

    if request.method == 'GET':
        return render_template('signup.html')

    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return "Username and Password required ❌"

    hashed_password = generate_password_hash(password)

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute(
        "SELECT * FROM users WHERE username=?",
        (username,)
    )

    existing_user = c.fetchone()

    if existing_user:
        conn.close()
        return "User already exists ❌"

    c.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, hashed_password)
    )

    conn.commit()
    conn.close()

    return redirect('/')

# 📊 Dashboard
@app.route('/dashboard')
def dashboard():

    if 'user' not in session:
        return redirect('/')

    user_folder = os.path.join(
        UPLOAD_FOLDER,
        session['user']
    )

    files = []

    if os.path.exists(user_folder):

        files = sorted(
            os.listdir(user_folder),
            key=lambda x: os.path.getmtime(
                os.path.join(user_folder, x)
            ),
            reverse=True
        )

        files = [
            f for f in files
            if not f.endswith('.sig')
            and not f.startswith('temp_')
        ]

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute('''
    SELECT action, filename, time
    FROM logs
    WHERE username=?
    ORDER BY time DESC
    ''', (session['user'],))

    logs = c.fetchall()

    c.execute('''
    SELECT token, filename, expiry_time
    FROM shared_links
    WHERE username=?
    ORDER BY id DESC
    ''', (session['user'],))

    shared_links = c.fetchall()

    conn.close()

    return render_template(
        'dashboard.html',
        user=session['user'],
        files=files,
        logs=logs,
        shared_links=shared_links
    )

# 🚪 Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

# 📤 Upload File
@app.route('/upload', methods=['POST'])
def upload():

    if 'user' not in session:
        return redirect('/')

    file = request.files['file']
    password = request.form['password']

    if file.filename == "":
        return redirect('/dashboard')

    filename = file.filename

    key = generate_key(password)
    cipher = Fernet(key)

    encrypted = cipher.encrypt(file.read())

    user_folder = os.path.join(
        UPLOAD_FOLDER,
        session['user']
    )

    os.makedirs(user_folder, exist_ok=True)

    file_path = os.path.join(user_folder, filename)

    with open(file_path, "wb") as f:
        f.write(encrypted)

    signature = private_key.sign(
        encrypted,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(file_path + ".sig", "wb") as f:
        f.write(signature)

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    ist = pytz.timezone('Asia/Kolkata')
    current_time = datetime.now(ist)

    c.execute(
        "INSERT INTO logs (username, action, filename, time) VALUES (?, ?, ?, ?)",
        (
            session['user'],
            "UPLOAD",
            filename,
            current_time.strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    conn.commit()
    conn.close()

    return redirect('/dashboard')

# 📥 Download File
@app.route('/download/<filename>', methods=['POST'])
def download(filename):

    if 'user' not in session:
        return redirect('/')

    password = request.form['password']

    key = generate_key(password)
    cipher = Fernet(key)

    user_folder = os.path.join(
        UPLOAD_FOLDER,
        session['user']
    )

    file_path = os.path.join(user_folder, filename)

    if not os.path.exists(file_path):
        return "❌ File not found"

    with open(file_path, "rb") as f:
        encrypted = f.read()

    try:
        with open(file_path + ".sig", "rb") as f:
            signature = f.read()
    except:
        return "❌ Signature missing"

    try:
        public_key.verify(
            signature,
            encrypted,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        return "❌ File integrity compromised!"

    try:
        decrypted = cipher.decrypt(encrypted)
    except:
        return "❌ Wrong password!"

    temp_path = os.path.join(
        user_folder,
        "temp_" + filename
    )

    with open(temp_path, "wb") as f:
        f.write(decrypted)

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    ist = pytz.timezone('Asia/Kolkata')
    current_time = datetime.now(ist)

    c.execute(
        "INSERT INTO logs (username, action, filename, time) VALUES (?, ?, ?, ?)",
        (
            session['user'],
            "DOWNLOAD",
            filename,
            current_time.strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    conn.commit()
    conn.close()

    return send_file(temp_path, as_attachment=True)

# 🔗 Share File
@app.route('/share', methods=['POST'])
def share():

    if 'user' not in session:
        return redirect('/')

    filename = request.form['filename']
    share_password = request.form['share_password']
    expiry_option = request.form['expiry']

    token = secrets.token_urlsafe(16)

    ist = pytz.timezone('Asia/Kolkata')

    if expiry_option == '24h':
        expiry_time = datetime.now(ist) + timedelta(hours=24)
    else:
        expiry_time = datetime.now(ist) + timedelta(days=7)

    password_hash = generate_password_hash(share_password)

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute('''
    INSERT INTO shared_links
    (token, filename, username, password_hash, expiry_time)
    VALUES (?, ?, ?, ?, ?)
    ''', (
        token,
        filename,
        session['user'],
        password_hash,
        expiry_time.isoformat()
    ))

    conn.commit()
    conn.close()

    return redirect('/dashboard')

# 🌐 Shared Access
@app.route('/shared/<token>', methods=['GET', 'POST'])
def shared(token):

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute(
        "SELECT filename, username, password_hash, expiry_time FROM shared_links WHERE token=?",
        (token,)
    )

    row = c.fetchone()
    conn.close()

    if not row:
        return "Invalid link ❌"

    filename, username, share_pwd_hash, expiry_time = row

    expiry_time = datetime.fromisoformat(expiry_time)

    ist = pytz.timezone('Asia/Kolkata')

    if datetime.now(ist) > expiry_time:
        return "Link expired ❌"

    if request.method == 'POST':

        share_pwd = request.form.get('share_password')
        file_pwd = request.form.get('file_password')

        if share_pwd_hash and not check_password_hash(
            share_pwd_hash,
            share_pwd
        ):
            return "Wrong share password ❌"

        user_folder = os.path.join(UPLOAD_FOLDER, username)
        file_path = os.path.join(user_folder, filename)

        if not os.path.exists(file_path):
            return "File not found ❌"

        with open(file_path, "rb") as f:
            encrypted = f.read()

        key = generate_key(file_pwd)
        cipher = Fernet(key)

        try:
            decrypted = cipher.decrypt(encrypted)
        except:
            return "Wrong file password ❌"

        temp_path = os.path.join(
            user_folder,
            "temp_" + filename
        )

        with open(temp_path, "wb") as f:
            f.write(decrypted)

        return send_file(temp_path, as_attachment=True)

    return render_template(
        'shared.html',
        token=token
    )

# ▶ Run App
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)

