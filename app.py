# app.py
from flask_mail import Mail, Message
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from supabase import create_client, Client
import secrets
import pytz
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
import base64
import hashlib
import random

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
# EMAIL CONFIG
# =========================

app.config['MAIL_SERVER'] = 'smtp.gmail.com'

app.config['MAIL_PORT'] = 465

app.config['MAIL_USE_TLS'] = False

app.config['MAIL_USE_SSL'] = True

app.config['MAIL_USERNAME'] = 'cryptix.1805@gmail.com'

app.config['MAIL_PASSWORD'] = 'xccprhpyoghixuch'

app.config['MAIL_TIMEOUT'] = 15

mail = Mail(app)

# =========================
# OTP STORAGE
# =========================

otp_store = {}

signup_store = {}

# =========================
# GENERATE USER RSA KEYS
# =========================

def generate_user_keys():

    private_key = rsa.generate_private_key(

        public_exponent=65537,

        key_size=2048

    )

    private_pem = private_key.private_bytes(

        encoding=
        serialization.Encoding.PEM,

        format=
        serialization.PrivateFormat.PKCS8,

        encryption_algorithm=
        serialization.NoEncryption()

    ).decode()

    public_pem = private_key.public_key().public_bytes(

        encoding=
        serialization.Encoding.PEM,

        format=
        serialization.PublicFormat.SubjectPublicKeyInfo

    ).decode()

    return private_pem, public_pem

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

    email = request.form['email']

    password = request.form['password']

    # =========================
    # FIND USER BY EMAIL
    # =========================

    result = supabase.table(
        "users"
    ).select("*").eq(

        "email",
        email

    ).execute()

    # =========================
    # USER NOT FOUND
    # =========================

    if not result.data:

        flash(
            "Email not registered ❌"
        )

        return redirect('/')

    user = result.data[0]

    # =========================
    # WRONG PASSWORD
    # =========================

    if not check_password_hash(

        user['password'],

        password

    ):

        flash(
            "Wrong password ❌"
        )

        return redirect('/')

    # =========================
    # LOGIN SUCCESS
    # =========================

    session['user'] = user['username']

    session['email'] = user['email']

    session['login_success'] = (
        "Logged in successfully ✅"
    )

    return redirect('/dashboard')
# =========================
# FORGOT PASSWORD
# =========================

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'POST':

        email = request.form[
            'email'
        ].strip().lower()

        # =========================
        # CHECK USER
        # =========================

        result = supabase.table(
            "users"
        ).select("*").eq(

            "email",
            email

        ).execute()

        if not result.data:

            flash(
                "Email not registered ❌"
            )

            return redirect(
                '/forgot-password'
            )

        # =========================
        # GENERATE OTP
        # =========================

        otp = str(
            random.randint(
                100000,
                999999
            )
        )

        # SAVE OTP

        otp_store[email] = {

            "otp": otp,

            "expires":
            datetime.now()
            + timedelta(minutes=5)

        }

        # =========================
        # SEND EMAIL
        # =========================

        try:

            msg = Message(

                'Secure Transfer Pro OTP',

                sender=
                app.config['MAIL_USERNAME'],

                recipients=[email]

            )

            msg.body = f"""

Your OTP for password recovery is:

{otp}

This OTP expires in 5 minutes.

Secure Transfer Pro
"""

            try:

                mail.send(msg)

            except Exception as e:

                print("MAIL ERROR:", e)

                return f"MAIL ERROR: {e}"

        except Exception as e:

            return render_template(

                'error.html',

                error_message=
                "Unable to send OTP email ❌"

            )

        flash(
            "OTP sent to your email ✅"
        )

        return redirect(
            f'/verify-otp?email={email}'
        )

    return render_template(
        'forgot_password.html'
    )
# =========================
# VERIFY SIGNUP OTP
# =========================

@app.route(
    '/verify-signup-otp',
    methods=['GET', 'POST']
)
def verify_signup_otp():

    email = request.args.get('email')

    # =========================
    # EMAIL NOT FOUND
    # =========================

    if email not in signup_store:

        flash(
            "Signup session expired ❌"
        )

        return redirect('/signup')

    # =========================
    # POST REQUEST
    # =========================

    if request.method == 'POST':

        entered_otp = request.form['otp']

        saved_data = signup_store[email]

        # =========================
        # CHECK OTP EXPIRY
        # =========================

        if datetime.now() > saved_data['expires']:

            del signup_store[email]

            flash(
                "OTP expired ❌"
            )

            return redirect('/signup')

        # =========================
        # VERIFY OTP
        # =========================

        if entered_otp != saved_data['otp']:

            flash(
                "Wrong OTP ❌"
            )

            return redirect(
                f'/verify-signup-otp?email={email}'
            )

        # =========================
        # GENERATE RSA KEYS
        # =========================

        private_key, public_key = (
            generate_user_keys()
        )

        # =========================
        # HASH PASSWORD
        # =========================

        hashed_password = generate_password_hash(

            saved_data['password']

        )

        # =========================
        # STORE USER
        # =========================

        supabase.table(
            "users"
        ).insert({

            "username":
            saved_data['username'],

            "email":
            email,

            "password":
            hashed_password,

            "public_key":
            public_key

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

            f"{saved_data['username']}_private.pem"

        )

        with open(
            private_key_path,
            "w"
        ) as f:

            f.write(private_key)

        # =========================
        # SEND WELCOME EMAIL
        # =========================

        try:

            msg = Message(

                'Welcome to Secure Transfer Pro',

                sender=
                app.config['MAIL_USERNAME'],

                recipients=[email]

            )

            msg.body = f"""

Hello {saved_data['username']},

Your account was verified successfully ✅

Welcome to Secure Transfer Pro 🔐

"""

            mail.send(msg)

        except:

            print(
                "Welcome email failed"
            )

        # =========================
        # REMOVE TEMP DATA
        # =========================

        del signup_store[email]

        flash(
            "Account created successfully ✅"
        )

        # =========================
        # DOWNLOAD PRIVATE KEY
        # =========================

        return send_file(

            private_key_path,

            as_attachment=True

        )

    return render_template(

        'verify_signup_otp.html',

        email=email

    )


# =========================
# VERIFY OTP
# =========================

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():

    email = request.args.get('email')

    if request.method == 'POST':

        entered_otp = request.form['otp']

        new_password = request.form['new_password']

        # =========================
        # CHECK OTP EXISTS
        # =========================

        if email not in otp_store:

            flash(
                "OTP expired ❌"
            )

            return redirect(
                '/forgot-password'
            )

        saved_data = otp_store[email]

        # =========================
        # CHECK EXPIRY
        # =========================

        if datetime.now() > saved_data['expires']:

            del otp_store[email]

            flash(
                "OTP expired ❌"
            )

            return redirect(
                '/forgot-password'
            )

        # =========================
        # VERIFY OTP
        # =========================

        if entered_otp != saved_data['otp']:

            flash(
                "Wrong OTP ❌"
            )

            return redirect(
                f'/verify-otp?email={email}'
            )

        # =========================
        # UPDATE PASSWORD
        # =========================

        hashed_password = generate_password_hash(
            new_password
        )

        supabase.table(
            "users"
        ).update({

            "password":
            hashed_password

        }).eq(

            "email",
            email

        ).execute()

        # REMOVE OTP

        del otp_store[email]

        flash(
            "Password reset successful ✅"
        )

        return redirect('/')

    return render_template(

        'verify_otp.html',

        email=email

    )
# =========================
# SIGNUP
# =========================
@app.route('/signup', methods=['GET', 'POST'])
def signup():

    if request.method == 'POST':

        username = request.form['username']

        email = request.form[
            'email'
        ].strip().lower()

        password = request.form['password']

        # =========================
        # CHECK USERNAME
        # =========================

        existing_user = supabase.table(
            "users"
        ).select("*").eq(

            "username",
            username

        ).execute()

        if existing_user.data:

            flash(
                "Username already exists ❌"
            )

            return redirect('/signup')

        # =========================
        # CHECK EMAIL
        # =========================

        existing_email = supabase.table(
            "users"
        ).select("*").eq(

            "email",
            email

        ).execute()

        if existing_email.data:

            flash(
                "Email already registered ❌"
            )

            return redirect('/signup')

        # =========================
        # GENERATE OTP
        # =========================

        otp = str(

            random.randint(
                100000,
                999999
            )

        )

        # =========================
        # STORE TEMP DATA
        # =========================

        signup_store[email] = {

            "username":
            username,

            "password":
            password,

            "otp":
            otp,

            "expires":
            datetime.now()
            + timedelta(minutes=5)

        }

        # =========================
        # SEND OTP EMAIL
        # =========================

        try:

            msg = Message(

                'Secure Transfer Pro Signup OTP',

                sender=
                app.config['MAIL_USERNAME'],

                recipients=[email]

            )

            msg.body = f"""

Hello {username},

Your OTP for account verification is:

{otp}

This OTP expires in 5 minutes.

Secure Transfer Pro
"""

            mail.send(msg)

        except Exception as e:

            return f"Email error: {e}"

        flash(
            "OTP sent to your email ✅"
        )

        return redirect(
            f'/verify-signup-otp?email={email}'
        )

    return render_template(
        'signup.html'
    )


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
    # FETCH FILES FROM DATABASE
    # =========================

    files_response = supabase.table(
        "uploaded_files"
    ).select(

        "filename"

    ).eq(

        "username",
        session['user']

    ).execute()

    files = [

        file['filename']

        for file in files_response.data

    ]
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

    file_password = request.form[
        'file_password'
    ]

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
    # GENERATE FILE HASH
    # =========================

    file_hash = hashlib.sha256(

        encrypted_data

    ).hexdigest()

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
    # SAVE FILE PASSWORD
    # =========================

    encoded_password = base64.b64encode(

        file_password.encode()

    ).decode()

    supabase.table(
        "file_passwords"
    ).insert({

        "username":
        session['user'],

        "filename":
        filename,

        "encrypted_password":
        encoded_password

    }).execute()

    # =========================
    # SAVE FILE HASH
    # =========================

    supabase.table(
        "file_signatures"
    ).insert({

        "username":
        session['user'],

        "filename":
        filename,

        "file_hash":
        file_hash

    }).execute()

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

    # =========================
    # SESSION CHECK
    # =========================

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

            "success": False,

            "error":
            "File not found ❌"

        })

    # =========================
    # FETCH IV
    # =========================

    file_data = supabase.table(
        "files"
    ).select(

        "iv"

    ).eq(

        "filename",
        filename

    ).eq(

        "username",
        session['user']

    ).execute()

    if not file_data.data:

        return jsonify({

            "success": False,

            "error":
            "IV not found ❌"

        })

    iv = file_data.data[0]['iv']

    # =========================
    # VERIFY FILE HASH
    # =========================

    hash_data = supabase.table(
        "file_signatures"
    ).select(

        "file_hash"

    ).eq(

        "filename",
        filename

    ).eq(

        "username",
        session['user']

    ).execute()

    if not hash_data.data:

        return jsonify({

            "success": False,

            "error":
            "File hash missing ❌"

        })

    stored_hash = hash_data.data[0][
        'file_hash'
    ]

    current_hash = hashlib.sha256(
        encrypted_file
    ).hexdigest()

    if current_hash != stored_hash:

        return jsonify({

            "success": False,

            "error":
            "❌ File Integrity Verification Failed"

        })

    # =========================
    # LOG DOWNLOAD
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
        "DOWNLOAD",

        "filename":
        filename,

        "time":
        current_time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    }).execute()

    # =========================
    # RETURN FILE + IV
    # =========================

    return jsonify({

        "success": True,

        "verified": True,

        "file":
        base64.b64encode(
            encrypted_file
        ).decode(),

        "iv":
        iv,

        "filename":
        filename

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

    # =========================
    # VERIFY FILE PASSWORD
    # =========================

    entered_password = request.form[
        'file_password'
    ]

    password_data = supabase.table(
        "file_passwords"
    ).select(

        "encrypted_password"

    ).eq(

        "filename",
        filename

    ).eq(

        "username",
        session['user']

    ).execute()

    if not password_data.data:

        return "Password not found ❌"

    stored_password = password_data.data[0][
        'encrypted_password'
    ]

    stored_password = base64.b64decode(

        stored_password

    ).decode()

    if entered_password != stored_password:

        return "Wrong password ❌"
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
        # DELETE FILE SIGNATURE
        # =========================

        supabase.table(
            "file_signatures"
        ).delete().eq(

            "filename",
            filename

        ).eq(

            "username",
            session['user']

        ).execute()

        # =========================
        # DELETE FILE PASSWORD
        # =========================

        supabase.table(
            "file_passwords"
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

    # =========================
    # INVALID LINK
    # =========================

    if not result.data:

        return render_template(

            "expired.html",

            message=
            "❌ Invalid Secure Link"

        )

    row = result.data[0]

    filename = row['filename']

    username = row['username']

    share_pwd_hash = row['password_hash']

    expiry_time = row['expiry_time']

    one_time = row['one_time']

    # =========================
    # EXPIRY CHECK
    # =========================

    if expiry_time != "One Time Access":

        expiry_date = datetime.fromisoformat(
            expiry_time
        )

        ist = pytz.timezone(
            'Asia/Kolkata'
        )

        if datetime.now(ist) > expiry_date:

            return render_template(

                "expired.html",

                message=
                "⌛ Secure Link Expired"

            )

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

            return jsonify({

                "success": False,

                "error":
                "❌ Wrong share password"

            })

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

            return jsonify({

                "success": False,

                "error":
                "❌ File not found"

            })

        # =========================
        # FETCH IV
        # =========================

        file_data = supabase.table(
            "files"
        ).select(

            "iv"

        ).eq(

            "filename",
            filename

        ).eq(

            "username",
            username

        ).execute()

        if not file_data.data:

            return jsonify({

                "success": False,

                "error":
                "❌ File metadata missing"

            })

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
        # RETURN FILE
        # =========================

        return jsonify({

            "success": True,

            "file":
            base64.b64encode(
                encrypted
            ).decode(),

            "iv":
            iv,

            "filename":
            filename

        })

    # =========================
    # RENDER PAGE
    # =========================

    return render_template(

        'shared.html',

        token=token

    )
# =========================
# WRONG FILE PASSWORD PAGE
# =========================

@app.route(
    '/wrong-file-password/<filename>'
)
def wrong_file_password(filename):

    return render_template(

        'wrong_file_password.html',

        filename=filename

    )
# =========================
# FORGOT FILE PASSWORD
# =========================

@app.route(
    '/recover-file-password/<filename>',
    methods=['GET', 'POST']
)
def recover_file_password(filename):

    # =========================
    # SESSION CHECK
    # =========================

    if 'user' not in session:

        return redirect('/')

    email = session['email']

    # =========================
    # SEND OTP
    # =========================

    if request.method == 'GET':

        otp = str(

            random.randint(
                100000,
                999999
            )

        )

        otp_store[email] = {

            "otp":
            otp,

            "expires":
            datetime.now()
            + timedelta(minutes=5)

        }

        try:

            msg = Message(

                'Recover File Password OTP',

                sender=
                app.config['MAIL_USERNAME'],

                recipients=[email]

            )

            msg.body = f"""

Your OTP to recover file password is:

{otp}

File:
{filename}

OTP expires in 5 minutes.

Secure Transfer Pro
"""

            mail.send(msg)

        except Exception as e:

            return f"Email error: {e}"

        flash(
            "OTP sent to your email ✅"
        )

        return render_template(

            'recover_file_password.html',

            filename=filename

        )

    # =========================
    # VERIFY OTP
    # =========================

    entered_otp = request.form['otp']

    if email not in otp_store:

        flash(
            "OTP expired ❌"
        )

        return redirect('/dashboard')

    saved_data = otp_store[email]

    # =========================
    # CHECK EXPIRY
    # =========================

    if datetime.now() > saved_data['expires']:

        del otp_store[email]

        flash(
            "OTP expired ❌"
        )

        return redirect('/dashboard')

    # =========================
    # WRONG OTP
    # =========================

    if entered_otp != saved_data['otp']:

        flash(
            "Wrong OTP ❌"
        )

        return redirect(

            f'/recover-file-password/{filename}'

        )

    # =========================
    # FETCH PASSWORD
    # =========================

    password_data = supabase.table(

        "file_passwords"

    ).select("*").eq(

        "filename",
        filename

    ).eq(

        "username",
        session['user']

    ).execute()

    if not password_data.data:

        flash(
            "Password not found ❌"
        )

        return redirect('/dashboard')

    encoded_password = password_data.data[0][
        'encrypted_password'
    ]

    recovered_password = base64.b64decode(

        encoded_password

    ).decode()

    # REMOVE OTP

    del otp_store[email]

    return render_template(

        'show_file_password.html',

        filename=filename,

        recovered_password=
        recovered_password

    )
# =========================
# CHANGE FILE PASSWORD PAGE
# =========================

@app.route(
    '/change-file-password/<filename>'
)
def change_file_password_page(filename):

    # SESSION CHECK

    if 'user' not in session:

        return redirect('/')

    # OPEN HTML PAGE

    return render_template(

        'change_file_password.html',

        filename=filename

    )

# =========================
# REPLACE FILE AFTER
# PASSWORD CHANGE
# =========================

@app.route(
    '/replace-file/<filename>',
    methods=['POST']
)
def replace_file(filename):

    # =========================
    # SESSION CHECK
    # =========================

    if 'user' not in session:

        return jsonify({

            "success": False,

            "message":
            "Unauthorized ❌"

        })

    try:

        # =========================
        # GET NEW FILE
        # =========================

        file = request.files['file']

        iv = request.form['iv']

        file_password = request.form[
            'file_password'
        ]

        encrypted_data = file.read()

        # =========================
        # GENERATE NEW HASH
        # =========================

        file_hash = hashlib.sha256(

            encrypted_data

        ).hexdigest()

        file_path = (
            f"{session['user']}/{filename}"
        )

        # =========================
        # DELETE OLD FILE
        # =========================

        supabase.storage.from_(
            "files"
        ).remove([

            file_path

        ])

        # =========================
        # UPLOAD NEW ENCRYPTED FILE
        # =========================

        supabase.storage.from_(
            "files"
        ).upload(

            file_path,

            encrypted_data

        )

        # =========================
        # UPDATE IV
        # =========================

        supabase.table(
            "files"
        ).update({

            "iv":
            iv

        }).eq(

            "filename",
            filename

        ).eq(

            "username",
            session['user']

        ).execute()

        # =========================
        # UPDATE RECOVERY PASSWORD
        # =========================

        encoded_password = (
            base64.b64encode(

                file_password.encode()

            ).decode()
        )

        supabase.table(
            "file_passwords"
        ).update({

            "encrypted_password":
            encoded_password

        }).eq(

            "filename",
            filename

        ).eq(

            "username",
            session['user']

        ).execute()

        # =========================
        # UPDATE FILE HASH
        # =========================

        supabase.table(
            "file_signatures"
        ).update({

            "file_hash":
            file_hash

        }).eq(

            "filename",
            filename

        ).eq(

            "username",
            session['user']

        ).execute()

        # =========================
        # SUCCESS
        # =========================

        return jsonify({

            "success": True,

            "message":
            "Password changed successfully ✅"

        })

    except Exception as e:

        return jsonify({

            "success": False,

            "message":
            f"Error: {e}"

        })
# =========================
# RUN APP
# =========================

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)

