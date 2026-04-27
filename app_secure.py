from flask import Flask, request, session, redirect, url_for, render_template_string
import pymysql
import os
import time
import random
import re  # Added for Strict Input Validation in Messaging
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super-secret-lab-key-2026-change-this")

# Security Configuration for File Uploads (ASVS 10.5.1, 10.2.1)
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt"}
MAX_UPLOAD_SIZE = 5 * 1024 * 1024
UPLOAD_FOLDER = 'secure_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_SIZE

# Security Configuration for Logins (ASVS 6.3.1)
RATE_LIMIT_WINDOW = 300
MAX_FAILED_LOGINS = 5
failed_logins = {}

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "student_portal_lab_secure"),
    "cursorclass": pymysql.cursors.DictCursor,
    "autocommit": True
}

def get_db():
    return pymysql.connect(**DB_CONFIG)

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def current_user():
    uid = session.get("user_id")
    if not uid: return None
    with get_db().cursor() as cur:
        cur.execute("SELECT id, username, role, full_name, email, phone FROM users WHERE id = %s", (uid,))
        return cur.fetchone()

def rate_limit_check(username: str) -> bool:
    now = time.time()
    if username not in failed_logins: return True
    failed_logins[username] = [t for t in failed_logins[username] if now - t < RATE_LIMIT_WINDOW]
    return len(failed_logins[username]) < MAX_FAILED_LOGINS

def record_failed_login(username: str):
    if username not in failed_logins: failed_logins[username] = []
    failed_logins[username].append(time.time())

# ====================== LOGIN (User Story 1) ======================
@app.route("/login", methods=["GET", "POST"])
def login():
    error_msg = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        captcha = request.form.get("captcha", "").strip()

        if not rate_limit_check(username):
            error_msg = "Too many failed attempts. Try again in 5 minutes."
        else:
            expected = session.pop("captcha_answer", None)
            if not expected or not captcha.isdigit() or int(captcha) != expected:
                record_failed_login(username)
                error_msg = "Invalid Security Check (CAPTCHA)."
            elif not username or not password or len(username) > 50:
                record_failed_login(username)
                error_msg = "Invalid username or password."
            else:
                with get_db().cursor() as cur:
                    cur.execute("SELECT id, username, password_hash, role FROM users WHERE username = %s", (username,))
                    user = cur.fetchone()

                if not user or not check_password_hash(user["password_hash"], password):
                    record_failed_login(username)
                    error_msg = "Invalid username or password."
                else:
                    failed_logins.pop(username, None)
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    session["role"] = user["role"]
                    return redirect(url_for("index"))

    a, b = random.randint(1, 10), random.randint(1, 10)
    session["captcha_answer"] = a + b
    
    return render_template_string("""
    <!DOCTYPE html><html lang="en"><head><title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-light d-flex align-items-center justify-content-center vh-100">
        <div class="card p-4 shadow-sm" style="width: 400px;">
            <h4 class="mb-4 text-center" style="color: #0f2c59;">Secure Portal Login</h4>
            {% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
            <form method="post">
                <input type="text" class="form-control mb-3" name="username" placeholder="Username" required>
                <input type="password" class="form-control mb-3" name="password" placeholder="Password" required>
                <label class="form-label">Security: {{ a }} + {{ b }} = ?</label>
                <input type="text" class="form-control mb-4" name="captcha" required>
                <button type="submit" class="btn w-100 text-white" style="background-color: #0f2c59;">Sign In</button>
            </form>
        </div>
    </body></html>
    """, a=a, b=b, error=error_msg)

# ====================== DASHBOARD ======================
@app.route("/")
def index():
    user = current_user()
    return render_template_string("""
    <!DOCTYPE html><html lang="en"><head><title>Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
    <style>.navbar{background-color: #0f2c59;}</style></head>
    <body class="bg-light">
        <nav class="navbar navbar-dark p-3 shadow-sm">
            <div class="container d-flex justify-content-between">
                <a class="navbar-brand fw-bold" href="/"><i class="bi bi-mortarboard-fill me-2"></i>State University</a>
                {% if user %}
                    <div class="text-white"><span class="me-3">{{ user.username }} ({{ user.role }})</span>
                    <a href="/logout" class="btn btn-outline-light btn-sm">Logout</a></div>
                {% endif %}
            </div>
        </nav>
        <div class="container mt-5">
            {% if user %}
                <div class="row g-4">
                    <div class="col-md-4"><div class="card p-4 text-center shadow-sm h-100"><i class="bi bi-file-earmark-text fs-1 text-primary"></i><h4 class="mt-2">Assignments</h4><a href="/assignment" class="btn btn-primary mt-3">Upload Work</a></div></div>
                    <div class="col-md-4"><div class="card p-4 text-center shadow-sm h-100"><i class="bi bi-chat-square-dots fs-1 text-success"></i><h4 class="mt-2">Messages</h4><a href="/message" class="btn btn-success mt-3">Open Inbox</a></div></div>
                    <div class="col-md-4"><div class="card p-4 text-center shadow-sm h-100"><i class="bi bi-gear fs-1 text-secondary"></i><h4 class="mt-2">Settings</h4><a href="/profile" class="btn btn-secondary mt-3">Edit Profile</a></div></div>
                </div>
            {% else %}
                <div class="text-center mt-5"><h3>Authentication Required</h3><a href="/login" class="btn btn-primary mt-3">Go to Login</a></div>
            {% endif %}
        </div>
    </body></html>
    """, user=user)

# ====================== ASSIGNMENTS (User Story 2) ======================
@app.route("/assignment", methods=["GET", "POST"])
def assignment():
    user = current_user()
    if not user: return redirect(url_for('login'))
    
    msg, msg_type = None, ""
    if request.method == "POST":
        if 'file' not in request.files:
            msg, msg_type = "No file part submitted.", "danger"
        else:
            file = request.files['file']
            if file.filename == '':
                msg, msg_type = "No file selected.", "danger"
            elif file and allowed_file(file.filename):
                # MITRE T1190 / ASVS 10.5.1: secure_filename strips directory traversal payloads (e.g. ../../)
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                msg, msg_type = f"Success! {filename} was securely uploaded.", "success"
            else:
                msg, msg_type = "Invalid file type. Only PDF, DOC, DOCX, TXT are allowed.", "danger"

    return render_template_string("""
    <!DOCTYPE html><html lang="en"><head><title>Assignments</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-light"><div class="container mt-5">
        <a href="/" class="btn btn-outline-secondary mb-3">← Back to Dashboard</a>
        <div class="card shadow-sm"><div class="card-header bg-primary text-white"><h4>Submit Assignment</h4></div>
        <div class="card-body">
            {% if msg %}<div class="alert alert-{{ msg_type }}">{{ msg }}</div>{% endif %}
            <form method="post" enctype="multipart/form-data">
                <div class="mb-3">
                    <label class="form-label text-muted">Select File (PDF, DOC, DOCX, TXT only)</label>
                    <input type="file" class="form-control" name="file" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Upload Securely</button>
            </form>
        </div></div>
    </div></body></html>
    """, msg=msg, msg_type=msg_type)

# ====================== MESSAGES (User Story 3) ======================
@app.route("/message", methods=["GET", "POST"])
def message():
    user = current_user()
    if not user: return redirect(url_for('login'))
    
    msg, msg_type = None, ""
    if request.method == "POST":
        recipient = request.form.get("recipient", "").strip()
        content = request.form.get("content", "").strip()
        
        # STRICT INPUT VALIDATION: Check for HTML tags or script patterns
        # This regex looks for anything resembling <tag> or </tag>
        if re.search(r'<[^>]*>', content) or re.search(r'<[^>]*>', recipient):
            msg, msg_type = "Security Alert: HTML tags and scripts are not allowed in messages.", "danger"
        else:
            # Even if it passes validation, escaping is a good defense-in-depth measure
            safe_recipient = escape(recipient)
            safe_content = escape(content)
            
            # Simulated database insert
            msg, msg_type = f"Message securely processed and sent to {safe_recipient}.", "success"

    return render_template_string("""
    <!DOCTYPE html><html lang="en"><head><title>Messages</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-light"><div class="container mt-5">
        <a href="/" class="btn btn-outline-secondary mb-3">← Back to Dashboard</a>
        <div class="card shadow-sm"><div class="card-header bg-success text-white"><h4>Send Secure Message</h4></div>
        <div class="card-body">
            {% if msg %}<div class="alert alert-{{ msg_type }}">{{ msg }}</div>{% endif %}
            <form method="post">
                <div class="mb-3"><label class="form-label">Recipient Username</label><input type="text" class="form-control" name="recipient" required></div>
                <div class="mb-3"><label class="form-label">Message Content</label><textarea class="form-control" name="content" rows="4" required></textarea></div>
                <button type="submit" class="btn btn-success w-100">Send Message</button>
            </form>
        </div></div>
    </div></body></html>
    """, msg=msg, msg_type=msg_type)

# ====================== PROFILE (User Story 4) ======================
@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = current_user()
    if not user: return redirect(url_for('login'))
    
    msg, msg_type = None, ""
    if request.method == "POST":
        new_email = request.form.get("email")
        password_confirm = request.form.get("password_confirm")

        # MITRE T1098 / ASVS 6.2.1: Require Re-authentication for sensitive changes
        with get_db().cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE id = %s", (user['id'],))
            db_user = cur.fetchone()

        if not check_password_hash(db_user['password_hash'], password_confirm):
            msg, msg_type = "Authentication Failed: Incorrect current password.", "danger"
        else:
            # ASVS 4.1.3: Access Control enforced by strictly using the session's user['id']
            with get_db().cursor() as cur:
                cur.execute("UPDATE users SET email = %s WHERE id = %s", (new_email, user['id']))
            msg, msg_type = "Profile securely updated.", "success"
            user['email'] = new_email # Update local view

    return render_template_string("""
    <!DOCTYPE html><html lang="en"><head><title>Profile Settings</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-light"><div class="container mt-5">
        <a href="/" class="btn btn-outline-secondary mb-3">← Back to Dashboard</a>
        <div class="card shadow-sm"><div class="card-header bg-secondary text-white"><h4>Update Profile</h4></div>
        <div class="card-body">
            {% if msg %}<div class="alert alert-{{ msg_type }}">{{ msg }}</div>{% endif %}
            <form method="post">
                <div class="mb-3"><label class="form-label">Email Address</label>
                <input type="email" class="form-control" name="email" value="{{ user.email }}" required></div>
                
                <hr>
                <p class="text-danger fw-bold"><small>Security Check: Please confirm your password to save changes.</small></p>
                <div class="mb-3"><label class="form-label">Current Password</label>
                <input type="password" class="form-control" name="password_confirm" required></div>
                
                <button type="submit" class="btn btn-secondary w-100">Save Changes</button>
            </form>
        </div></div>
    </div></body></html>
    """, user=user, msg=msg, msg_type=msg_type)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
