import sqlite3
import os, base64
from flask import send_file
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"  # change later

# 🧑‍💻 Dummy user database (for now)
users = {
    "admin": generate_password_hash("1234")
}
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 🔐 Generate encryption key
def generate_key(password):
    return base64.urlsafe_b64encode(password.ljust(32).encode())

# 🔑 Load RSA keys
with open("private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

with open("public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

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

    c.execute("SELECT password FROM users WHERE username=?", (username,))
    result = c.fetchone()

    conn.close()

    if result and check_password_hash(result[0], password):
        session['user'] = username
        return redirect('/dashboard')
    else:
        return render_template("login.html", error="❌ Invalid credentials")

# 📊 Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')

    user_folder = os.path.join(UPLOAD_FOLDER, session['user'])

    files = []

    if os.path.exists(user_folder):
        files = os.listdir(user_folder)

        # ❗ IMPORTANT: remove .sig files
        files = [f for f in files if not f.endswith(".sig") and not f.startswith("temp_")]

    # logs
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("SELECT action, filename, time FROM logs WHERE username=?", (session['user'],))
    logs = c.fetchall()

    conn.close()

    return render_template("dashboard.html", user=session['user'], files=files, logs=logs)


# 🚪 Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')
@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session:
        return redirect('/')

    file = request.files['file']
    password = request.form['password']

    if file.filename == "":
        return redirect('/dashboard')

    filename = file.filename

    # 🔐 Encryption
    key = generate_key(password)
    cipher = Fernet(key)

    encrypted = cipher.encrypt(file.read())

    # 📂 Create user folder
    user_folder = os.path.join(UPLOAD_FOLDER, session['user'])
    os.makedirs(user_folder, exist_ok=True)

    file_path = os.path.join(user_folder, filename)

    # 💾 SAVE FILE (THIS WAS MISSING ❗)
    with open(file_path, "wb") as f:
        f.write(encrypted)

    # ✍️ RSA Signature
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

    # 📝 Logging
    import sqlite3
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("INSERT INTO logs (username, action, filename) VALUES (?, ?, ?)",
              (session['user'], "UPLOAD", filename))

    conn.commit()
    conn.close()

    return redirect('/dashboard')
@app.route('/download/<filename>', methods=['POST'])
def download(filename):
    # 🔐 Check login
    if 'user' not in session:
        return redirect('/')

    password = request.form['password']

    # 🔑 Generate encryption key
    key = generate_key(password)
    cipher = Fernet(key)

    # 📂 User-specific folder (Authorization)
    user_folder = os.path.join(UPLOAD_FOLDER, session['user'])
    file_path = os.path.join(user_folder, filename)

    # ❌ Check file exists
    if not os.path.exists(file_path):
        return "❌ File not found", 404

    # 📖 Read encrypted file
    with open(file_path, "rb") as f:
        encrypted = f.read()

    # 📖 Read signature
    try:
        with open(file_path + ".sig", "rb") as f:
            signature = f.read()
    except:
        return "❌ Signature missing", 400

    # 🔍 VERIFY SIGNATURE (Integrity)
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
        return "❌ File integrity compromised!", 400

    # 🔓 DECRYPT FILE (Confidentiality)
    try:
        decrypted = cipher.decrypt(encrypted)
    except:
        return "❌ Wrong password!", 400

    # 💾 Create temporary file
    temp_path = os.path.join(user_folder, "temp_" + filename)

    with open(temp_path, "wb") as f:
        f.write(decrypted)

    # 📝 LOG DOWNLOAD (Accountability)
    import sqlite3
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("INSERT INTO logs (username, action, filename) VALUES (?, ?, ?)",
              (session['user'], "DOWNLOAD", filename))

    conn.commit()
    conn.close()

    # 📤 Send file
    return send_file(temp_path, as_attachment=True)
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # user table
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
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    conn.commit()
    conn.close()

init_db()
@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = generate_password_hash(request.form['password'])

    import sqlite3
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
    except:
        conn.close()
        return render_template("login.html", error="❌ User already exists")

    conn.close()
    return render_template("login.html", error="✔ Account created. Please login")
# ▶ Run
import os

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)