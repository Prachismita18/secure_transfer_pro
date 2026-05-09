# app.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
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
    flash,
    jsonify
)


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
@app.route('/login')
def login_page():
    return redirect('/')
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

        # =========================
        # CHECK EXISTING USER
        # =========================

        existing_user = supabase.table(
            "users"
        ).select("*").eq(
            "username",
            username
        ).execute()

        if existing_user.data:

            flash("User already exists ❌")

            return redirect('/signup')

        # =========================
        # GENERATE USER RSA KEYS
        # =========================

        private_key, public_key = (
            generate_user_keys()
        )

        # =========================
        # STORE USER
        # =========================

        supabase.table("users").insert({

            "username": username,
            "password": hashed_password,
            "public_key": public_key

        }).execute()

        # =========================
        # SAVE PRIVATE KEY
        # =========================

        os.makedirs(
            "user_private_keys",
            exist_ok=True
        )

        private_key_path = os.path.join(
            "user_private_keys",
            f"{username}_private.pem"
        )

        with open(private_key_path, "w") as f:
            f.write(private_key)

        flash(
            "Account created. Save your private key 🔐"
        )

        # =========================
        # DOWNLOAD PRIVATE KEY
        # =========================

        return send_file(
            private_key_path,
            as_attachment=True
        )

    return render_template('signup.html')
# =========================
# DASHBOARD
# =========================
@app.route('/dashboard')
def dashboard():

    # =========================
    # SESSION CHECK
    # =========================

    if 'user' not in session:
        return redirect('/')

    # =========================
    # LOGIN MESSAGE
    # =========================

    login_message = session.pop(
        'login_success',
        None
    )

    # =========================
    # FETCH FILES
    # =========================

    files = []

    response = supabase.storage.from_(
        "files"
    ).list(
        path=session['user']
    )

    for item in response:

        if item.get("id"):

            name = item['name']

            # REMOVE TEMP + SIG FILES

            if (
                not name.endswith(".sig")
                and not name.startswith("temp_")
            ):

                files.append(name)

    # =========================
    # REMOVE DUPLICATES
    # =========================

    files = list(
        dict.fromkeys(files)
    )

    # =========================
    # FETCH FILE TIMES
    # =========================

    file_times_response = supabase.table(
        "uploaded_files"
    ).select("*").eq(

        "username",
        session['user']

    ).execute()

    file_times = file_times_response.data

    # =========================
    # SORT FILES BY TIME
    # =========================

    files = sorted(

        files,

        key=lambda x:

        next(

            (

                f['uploaded_at']

                for f in file_times

                if f['filename'] == x

            ),

            ""

        ),

        reverse=True

    )

    # =========================
    # FETCH LOGS
    # =========================

    logs_response = supabase.table(
        "logs"
    ).select("*").eq(

        "username",
        session['user']

    ).execute()

    logs = logs_response.data[::-1]

    # =========================
    # FETCH SHARED LINKS
    # =========================

    shared_response = supabase.table(
        "shared_links"
    ).select("*").eq(

        "username",
        session['user']

    ).execute()

    shared_links = sorted(

        shared_response.data,

        key=lambda x:
        x['created_at'],

        reverse=True

    )

    # =========================
    # RENDER DASHBOARD
    # =========================

    return render_template(

        'dashboard.html',

        user=session['user'],

        files=files,

        file_times=file_times,

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

    # =========================
    # SESSION CHECK
    # =========================

    if 'user' not in session:
        return redirect('/')

    # =========================
    # GET FILE + IV
    # =========================

    file = request.files['file']

    iv = request.form['iv']

    if file.filename == "":
        return redirect('/dashboard')

    filename = file.filename

    # =========================
    # CHECK EXISTING FILE
    # =========================

    existing_file = supabase.table(
        "uploaded_files"
    ).select("*").eq(

        "username",
        session['user']

    ).eq(

        "filename",
        filename

    ).execute()

    if existing_file.data:

        return jsonify({

            "success": False,

            "message":
            "⚠ File already exists"

        })

    # =========================
    # READ ENCRYPTED FILE
    # =========================

    encrypted_data = file.read()

    # =========================
    # UPLOAD TO SUPABASE STORAGE
    # =========================

    try:

        supabase.storage.from_(
            "files"
        ).upload(

        f"{session['user']}/{filename}",

        encrypted_data

    )

    except:

        return jsonify({

            "success": False,

            "message":
            "⚠ File already exists"

        })

    # =========================
    # CURRENT TIME
    # =========================

    ist = pytz.timezone(
        'Asia/Kolkata'
    )

    current_time = datetime.now(
        ist
    )

    # =========================
    # SAVE FILE METADATA
    # =========================

    supabase.table(
        "files"
    ).insert({

        "username":
        session['user'],

        "filename":
        filename,

        "iv":
        iv

    }).execute()

    # =========================
    # SAVE UPLOAD TIME
    # =========================

    supabase.table(
        "uploaded_files"
    ).insert({

        "username":
        session['user'],

        "filename":
        filename,

        "uploaded_at":
        current_time.isoformat()

    }).execute()

    # =========================
    # RSA DIGITAL SIGNATURE
    # =========================

    signature = private_key.sign(

        encrypted_data,

        padding.PSS(

            mgf=padding.MGF1(
                hashes.SHA256()
            ),

            salt_length=
            padding.PSS.MAX_LENGTH

        ),

        hashes.SHA256()

    )

    # =========================
    # SAVE SIGNATURE
    # =========================

    os.makedirs(

        "temp_signatures",

        exist_ok=True

    )

    sig_path = os.path.join(

        "temp_signatures",

        filename + ".sig"

    )

    with open(sig_path, "wb") as f:

        f.write(signature)

    # =========================
    # LOGS
    # =========================

    supabase.table(
        "logs"
    ).insert({

        "username":
        session['user'],

        "action":
        "UPLOAD",

        "filename":
        filename,

        "time":
        current_time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    }).execute()

    # =========================
    # RESPONSE
    # =========================

    return jsonify({

        "success": True,

        "message":
        "🔐 End-to-End Encrypted Upload Successful"

    })

# =========================
# DOWNLOAD FILE
# =========================
@app.route('/download/<filename>', methods=['GET'])
def download(filename):

    if 'user' not in session:
        return redirect('/')

    # =========================
    # DOWNLOAD ENCRYPTED FILE
    # =========================

    try:

        encrypted_file = (

            supabase.storage
            .from_("files")
            .download(
                f"{session['user']}/{filename}"
            )

        )

    except:

        return jsonify({

            "error": "File not found"

        })

    # =========================
    # FETCH IV
    # =========================

    file_data = supabase.table("files").select(

        "iv"

    ).eq(

        "filename",
        filename

    ).eq(

        "username",
        session['user']

    ).execute()

    iv = file_data.data[0]['iv']

    # =========================
    # LOGS
    # =========================

    ist = pytz.timezone(
        'Asia/Kolkata'
    )

    current_time = datetime.now(ist)

    supabase.table("logs").insert({

        "username": session['user'],

        "action": "DOWNLOAD",

        "filename": filename,

        "time": current_time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    }).execute()

    # =========================
    # RETURN FILE + IV
    # =========================

    return jsonify({

        "file": base64.b64encode(
            encrypted_file
        ).decode(),

        "iv": iv

    })

# =========================
# DELETE FILE
# =========================
@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):

    # =========================
    # SESSION CHECK
    # =========================

    if 'user' not in session:
        return redirect('/')

    try:

        file_path = (
            f"{session['user']}/{filename}"
        )

        # =========================
        # DELETE FROM STORAGE
        # =========================

        delete_response = supabase.storage.from_(
            "files"
        ).remove([

            file_path

        ])

        print(
            "DELETE RESPONSE:",
            delete_response
        )

        # =========================
        # DELETE FROM FILES TABLE
        # =========================

        supabase.table(
            "files"
        ).delete().eq(

            "filename",
            filename

        ).eq(

            "username",
            session['user']

        ).execute()

        # =========================
        # DELETE FROM UPLOADED FILES
        # =========================

        supabase.table(
            "uploaded_files"
        ).delete().eq(

            "filename",
            filename

        ).eq(

            "username",
            session['user']

        ).execute()

        # =========================
        # DELETE SHARED LINKS
        # =========================

        supabase.table(
            "shared_links"
        ).delete().eq(

            "filename",
            filename

        ).eq(

            "username",
            session['user']

        ).execute()

        # =========================
        # DELETE OLD LOGS
        # =========================

        supabase.table(
            "logs"
        ).delete().eq(

            "filename",
            filename

        ).eq(

            "username",
            session['user']

        ).execute()

        # =========================
        # ADD DELETE LOG
        # =========================

        ist = pytz.timezone(
            'Asia/Kolkata'
        )

        current_time = datetime.now(
            ist
        )

        supabase.table(
            "logs"
        ).insert({

            "username":
            session['user'],

            "action":
            "DELETE",

            "filename":
            filename,

            "time":
            current_time.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        }).execute()

    except Exception as e:

        return f"Delete failed ❌ {e}"

    return redirect('/dashboard')
# =========================
# SHARE FILE
# =========================
@app.route('/share', methods=['POST'])
def share():

    # =========================
    # SESSION CHECK
    # =========================

    if 'user' not in session:
        return redirect('/')

    # =========================
    # FORM DATA
    # =========================

    filename = request.form['filename']

    share_password = request.form[
        'share_password'
    ]

    expiry = request.form['expiry']

    # =========================
    # TOKEN
    # =========================

    token = secrets.token_urlsafe(16)

    # =========================
    # TIMEZONE
    # =========================

    ist = pytz.timezone(
        'Asia/Kolkata'
    )

    current_time = datetime.now(
        ist
    )

    # =========================
    # ONE TIME OPTION
    # =========================

    one_time = False

    # =========================
    # EXPIRY
    # =========================

    if expiry == "one_time":

        one_time = True

        expiry_time = "One Time Access"

    elif expiry == "24h":

        expiry_time = (

            current_time

            + timedelta(hours=24)

        ).isoformat()

    elif expiry == "7d":

        expiry_time = (

            current_time

            + timedelta(days=7)

        ).isoformat()

    # =========================
    # SAVE LINK
    # =========================

    supabase.table(
        "shared_links"
    ).insert({

        "token": token,

        "filename": filename,

        "username": session['user'],

        "password_hash":
        generate_password_hash(
            share_password
        ),

        "expiry_time":
        expiry_time,

        "one_time":
        one_time,

        "created_at":
        current_time.isoformat()

    }).execute()

    # =========================
    # RESPONSE
    # =========================

    return jsonify({

        "success": True,

        "message":
        "🔗 Secure share link created"

    })

# =========================
# SHARED ACCESS
# =========================
@app.route('/shared/')
def shared_home():
    return "Invalid shared link ❌"
@app.route('/shared/<token>', methods=['GET', 'POST'])
def shared(token):

    # =========================
    # FETCH LINK
    # =========================

    result = supabase.table(
        "shared_links"
    ).select("*").eq(
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

    one_time = row['one_time']

    # =========================
    # SKIP EXPIRY CHECK
    # FOR ONE-TIME LINKS
    # =========================

    if expiry_time != "One Time Access":

        expiry_time = datetime.fromisoformat(
            expiry_time
        )

        ist = pytz.timezone(
            'Asia/Kolkata'
        )

        if datetime.now(ist) > expiry_time:

            return "Link expired ❌"
    # =========================
    # POST REQUEST
    # =========================

    if request.method == 'POST':

        share_pwd = request.form.get(
            'share_password'
        )

        file_pwd = request.form.get(
            'file_password'
        )

        # =========================
        # VERIFY SHARE PASSWORD
        # =========================

        if share_pwd_hash and not check_password_hash(

            share_pwd_hash,
            share_pwd

        ):

            return "Wrong share password ❌"

        # =========================
        # DOWNLOAD ENCRYPTED FILE
        # =========================

        try:

            encrypted = (
                supabase.storage
                .from_("files")
                .download(
                    f"{username}/{filename}"
                )
            )

        except:

            return "File not found ❌"

        # =========================
        # DECRYPT FILE
        # =========================
        # =========================
        # FETCH IV
        # =========================

        file_data = supabase.table("files").select(
        "iv"
        ).eq(
            "filename",
            filename
        ).eq(
            "username",
            username
        ).execute()

        iv = file_data.data[0]['iv']

        
        # =========================
        # DELETE ONE-TIME LINK
        # =========================

        if one_time:

            supabase.table(
                "shared_links"
            ).delete().eq(

                "token",
                token

            ).execute()

        # =========================
        # SEND FILE
        # =========================

        # =========================
        # RETURN ENCRYPTED FILE
        # =========================

        return jsonify({

            "file": base64.b64encode(
            encrypted
        ).decode(),

        "iv": iv,

        "filename": filename

        })

    # =========================
    # RENDER PAGE
    # =========================

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

