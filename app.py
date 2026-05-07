# app.py
from supabase import create_client, Client
import secrets
import pytz
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
import base64

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    send_file,
    flash
)

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# =========================
# FLASK APP
# =========================

app = Flask(__name__)
app.secret_key = "supersecretkey"

# =========================
# SUPABASE CONNECTION
# =========================

url = "https://rrvnbxivvcyrajydbfrj.supabase.co"

key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJydm5ieGl2dmN5cmFqeWRiZnJqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzgwODE3MTAsImV4cCI6MjA5MzY1NzcxMH0.KrxIfaPbIT3skEjR5mL6wMLMhdaRYaPO9lk86rkUBj8"

supabase: Client = create_client(url, key)

# =========================
# ENCRYPTION KEY GENERATOR
# =========================

def generate_key(password):
    return base64.urlsafe_b64encode(password.ljust(32).encode())

# =========================
# LOAD RSA KEYS
# =========================

with open("private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

with open("public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# =========================
# HOME PAGE
# =========================

@app.route('/')
def home():
    return render_template('login.html')

# =========================
# LOGIN
# =========================

@app.route('/login', methods=['POST'])
def login():

    username = request.form['username']
    password = request.form['password']

    result = supabase.table("users").select("*").eq(
        "username",
        username
    ).execute()

    # ❌ User not found
    if not result.data:

        flash("User does not exist ❌")

        return redirect('/')

    user = result.data[0]

    # ❌ Wrong password
    if not check_password_hash(user['password'], password):

        flash("Wrong password ❌")

        return redirect('/')

    # ✅ Login success
    session['user'] = username

    session['login_success'] = "Logged in successfully ✅"

    return redirect('/dashboard')
# =========================
# SIGNUP
# =========================

@app.route('/signup', methods=['GET', 'POST'])
def signup():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        # 🔍 Check if user already exists
        existing_user = supabase.table("users").select("*").eq(
            "username",
            username
        ).execute()

        # ❌ User already exists
        if existing_user.data:

            flash("User already exists ❌")

            return redirect('/signup')

        # ✅ Create new user
        supabase.table("users").insert({
            "username": username,
            "password": hashed_password
        }).execute()

        flash("Account created successfully ✅")

        return redirect('/')

    return render_template('signup.html')

# =========================
# DASHBOARD
# =========================

@app.route('/dashboard')
def dashboard():

    if 'user' not in session:
        return redirect('/')

    # =========================
    # LOGIN SUCCESS MESSAGE
    # =========================

    login_message = session.pop(
        'login_success',
        None
    )

    # =========================
    # FETCH FILES
    # =========================
    files = []

    response = supabase.storage.from_("files").list(
    path=session['user']
    )

    for item in response:

        if item.get("id"):

         name = item['name']

        if (
            not name.endswith(".sig")
            and not name.startswith("temp_")
        ):

            files.append(name)

    files = list(dict.fromkeys(files))

    files.reverse()

    # =========================
    # FETCH LOGS
    # =========================

    logs_response = supabase.table("logs").select("*").eq(
        "username",
        session['user']
    ).execute()

    logs = logs_response.data[::-1]

    # =========================
    # FETCH SHARED LINKS
    # =========================

    shared_response = supabase.table("shared_links").select("*").eq(
        "username",
        session['user']
    ).execute()

    shared_links = shared_response.data[::-1]

    return render_template(
        'dashboard.html',
        user=session['user'],
        files=files,
        logs=logs,
        shared_links=shared_links,
        login_message=login_message
    )

# =========================
# LOGOUT
# =========================

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

# =========================
# UPLOAD FILE
# =========================

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

    # =========================
    # UPLOAD TO SUPABASE STORAGE
    # =========================

    supabase.storage.from_("files").upload(
        f"{session['user']}/{filename}",
        encrypted
    )

    # =========================
    # RSA SIGNATURE
    # =========================

    signature = private_key.sign(
        encrypted,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # SAVE SIGNATURE TEMPORARILY
    temp_sig_folder = "temp_signatures"
    os.makedirs(temp_sig_folder, exist_ok=True)

    sig_path = os.path.join(
        temp_sig_folder,
        filename + ".sig"
    )

    with open(sig_path, "wb") as f:
        f.write(signature)

    # =========================
    # LOGS
    # =========================

    ist = pytz.timezone('Asia/Kolkata')

    current_time = datetime.now(ist)

    supabase.table("logs").insert({
        "username": session['user'],
        "action": "UPLOAD",
        "filename": filename,
        "time": current_time.strftime("%Y-%m-%d %H:%M:%S")
    }).execute()

    return redirect('/dashboard')

# =========================
# DOWNLOAD FILE
# =========================

@app.route('/download/<filename>', methods=['POST'])
def download(filename):

    if 'user' not in session:
        return redirect('/')

    password = request.form['password']

    key = generate_key(password)
    cipher = Fernet(key)

    # =========================
    # DOWNLOAD ENCRYPTED FILE
    # =========================

    try:
        encrypted = supabase.storage.from_("files").download(
            f"{session['user']}/{filename}"
        )

    except:
        return "❌ File not found"

    # =========================
    # DECRYPT FILE
    # =========================

    try:
        decrypted = cipher.decrypt(encrypted)

    except:
        return "❌ Wrong password!"

    # =========================
    # TEMP DOWNLOAD FILE
    # =========================

    temp_folder = "temp_downloads"

    os.makedirs(temp_folder, exist_ok=True)

    temp_path = os.path.join(
        temp_folder,
        "temp_" + filename
    )

    with open(temp_path, "wb") as f:
        f.write(decrypted)

    # =========================
    # LOGS
    # =========================

    ist = pytz.timezone('Asia/Kolkata')

    current_time = datetime.now(ist)

    supabase.table("logs").insert({
        "username": session['user'],
        "action": "DOWNLOAD",
        "filename": filename,
        "time": current_time.strftime("%Y-%m-%d %H:%M:%S")
    }).execute()

    return send_file(temp_path, as_attachment=True)
# =========================
# DELETE FILE
# =========================
@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):

    if 'user' not in session:
        return redirect('/')

    try:

        file_path = f"{session['user']}/{filename}"

        # DELETE FROM SUPABASE STORAGE

        delete_response = supabase.storage.from_("files").remove([
            file_path
        ])

        print("DELETE RESPONSE:", delete_response)

        # DELETE SHARED LINKS

        supabase.table("shared_links").delete().eq(
            "filename",
            filename
        ).eq(
            "username",
            session['user']
        ).execute()

        # DELETE OLD LOGS OF THIS FILE

        supabase.table("logs").delete().eq(
            "filename",
            filename
        ).eq(
            "username",
            session['user']
        ).execute()

        # ADD DELETE LOG

        ist = pytz.timezone('Asia/Kolkata')

        current_time = datetime.now(ist)

        supabase.table("logs").insert({
            "username": session['user'],
            "action": "DELETE",
            "filename": filename,
            "time": current_time.strftime("%Y-%m-%d %H:%M:%S")
        }).execute()

    except Exception as e:

        return f"Delete failed ❌ {e}"

    return redirect('/dashboard')
# =========================
# SHARE FILE
# =========================

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

    supabase.table("shared_links").insert({
        "token": token,
        "filename": filename,
        "username": session['user'],
        "password_hash": password_hash,
        "expiry_time": expiry_time.isoformat()
    }).execute()

    # =========================
    # LOGS
    # =========================

    current_time = datetime.now(ist)

    supabase.table("logs").insert({
        "username": session['user'],
        "action": "SHARE LINK CREATED",
        "filename": filename,
        "time": current_time.strftime("%Y-%m-%d %H:%M:%S")
    }).execute()

    return redirect('/dashboard')

# =========================
# SHARED ACCESS
# =========================
@app.route('/shared/')
def shared_home():
    return "Invalid shared link ❌"

@app.route('/shared/<token>', methods=['GET', 'POST'])
def shared(token):

    result = supabase.table("shared_links").select("*").eq(
        "token",
        token
    ).execute()

    if not result.data:
        return "Invalid link ❌"

    row = result.data[0]

    filename = row['filename']
    username = row['username']
    share_pwd_hash = row['password_hash']
    expiry_time = row['expiry_time']

    expiry_time = datetime.fromisoformat(expiry_time)

    ist = pytz.timezone('Asia/Kolkata')

    if datetime.now(ist) > expiry_time:
        return "Link expired ❌"

    if request.method == 'POST':

        share_pwd = request.form.get('share_password')
        file_pwd = request.form.get('file_password')

        # =========================
        # CHECK SHARE PASSWORD
        # =========================

        if share_pwd_hash and not check_password_hash(
            share_pwd_hash,
            share_pwd
        ):
            return "Wrong share password ❌"

        # =========================
        # DOWNLOAD FILE FROM SUPABASE
        # =========================

        try:
            encrypted = supabase.storage.from_("files").download(
                f"{username}/{filename}"
            )

        except:
            return "File not found ❌"

        # =========================
        # DECRYPT FILE
        # =========================

        key = generate_key(file_pwd)
        cipher = Fernet(key)

        try:
            decrypted = cipher.decrypt(encrypted)

        except:
            return "Wrong file password ❌"

        # =========================
        # TEMP DOWNLOAD FILE
        # =========================

        temp_folder = "temp_downloads"

        os.makedirs(temp_folder, exist_ok=True)

        temp_path = os.path.join(
            temp_folder,
            "temp_" + filename
        )

        with open(temp_path, "wb") as f:
            f.write(decrypted)

        return send_file(
            temp_path,
            as_attachment=True
        )

    return render_template(
        'shared.html',
        token=token
    )

# =========================
# RUN APP
# =========================

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)

