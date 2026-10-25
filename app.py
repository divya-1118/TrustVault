import os
import re
import secrets
import uuid
from datetime import datetime
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Application configuration
app.config["SECRET_KEY"] = os.environ.get("TRUSTVAULT_SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("TRUSTVAULT_HTTPS", "") == "1"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///trustvault.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = os.path.join(app.instance_path, "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTENSIONS = {"txt", "md", "csv"}
MAX_FILE_SIZE = 5 * 1024 * 1024

# Database setup
db = SQLAlchemy(app)

# Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# User database model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    original_name = db.Column(db.String(255), nullable=False)
    storage_name = db.Column(db.String(36), unique=True, nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(40), nullable=False, default="General")
    summary = db.Column(db.Text, nullable=False, default="")
    sensitive_counts = db.Column(db.JSON, nullable=False, default=dict)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    analyzed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    document_id = db.Column(db.Integer, db.ForeignKey("document.id", ondelete="SET NULL"))
    action = db.Column(db.String(40), nullable=False)
    detail = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)


SENSITIVE_PATTERNS = {
    "Email addresses": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    "US phone numbers": re.compile(
        r"(?<!\w)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\w)"
    ),
    "US Social Security numbers": re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
    "Possible payment cards": re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
}


def _is_luhn_valid(value):
    digits = [int(character) for character in value if character.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def analyze_text(text):
    counts = {}
    for label, pattern in SENSITIVE_PATTERNS.items():
        matches = pattern.findall(text)
        if label == "Possible payment cards":
            matches = [match for match in matches if _is_luhn_valid(match)]
        counts[label] = len(matches)

    risk_score = min(
        100,
        counts["Email addresses"] * 5
        + counts["US phone numbers"] * 8
        + counts["US Social Security numbers"] * 35
        + counts["Possible payment cards"] * 40,
    )

    category_terms = {
        "Legal": ("agreement", "contract", "clause", "legal", "litigation", "terms"),
        "Finance": ("invoice", "payment", "revenue", "accounting", "bank", "tax"),
        "Human resources": ("employee", "payroll", "salary", "resume", "benefits", "hiring"),
        "Identity": ("passport", "driver license", "identity", "social security", "date of birth"),
    }
    lowered_text = text.lower()
    category_scores = {
        category: sum(lowered_text.count(term) for term in terms)
        for category, terms in category_terms.items()
    }
    category = max(category_scores, key=category_scores.get)
    if category_scores[category] == 0:
        category = "General"

    sentences = [
        re.sub(r"\s+", " ", sentence).strip()
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", text)
        if sentence.strip()
    ]
    summary_parts = []
    for sentence in sentences[:3]:
        if len(sentence) > 240:
            sentence = sentence[:237].rsplit(" ", 1)[0] + "..."
        summary_parts.append(sentence)
    summary = " ".join(summary_parts) or "No readable text was found."
    for label, pattern in SENSITIVE_PATTERNS.items():
        if label == "Possible payment cards":
            summary = pattern.sub(
                lambda match: "[redacted]" if _is_luhn_valid(match.group()) else match.group(),
                summary,
            )
        else:
            summary = pattern.sub("[redacted]", summary)

    return {
        "category": category,
        "summary": summary,
        "sensitive_counts": counts,
        "risk_score": risk_score,
    }


def record_activity(action, detail, document_id=None):
    db.session.add(
        AuditLog(
            owner_id=current_user.id,
            document_id=document_id,
            action=action,
            detail=detail[:255],
        )
    )
    db.session.commit()


@app.before_request
def protect_document_actions():
    if request.endpoint in {"upload_document", "reanalyze_document", "delete_document"}:
        token = session.get("csrf_token")
        submitted_token = request.form.get("csrf_token", "")
        if not token or not secrets.compare_digest(token, submitted_token):
            abort(400)


@app.context_processor
def inject_csrf_token():
    token = session.setdefault("csrf_token", secrets.token_urlsafe(32))
    return {"csrf_token": token}


# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


# Home page
@app.route("/")
def home():
    return render_template_string("""
    <h1>Welcome to TrustVault</h1>
    <p>Secure Document Sharing Platform</p>

    {% if current_user.is_authenticated %}
        <p>Welcome, {{ current_user.username }}!</p>
        <a href="{{ url_for('dashboard') }}">Dashboard</a>
        <br><br>
        <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
        <a href="{{ url_for('register') }}">Register</a>
        <br><br>
        <a href="{{ url_for('login') }}">Login</a>
    {% endif %}
    """)


# User registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("Please fill in all fields.")
        elif len(password) < 8:
            flash("Password must contain at least 8 characters.")
        elif User.query.filter_by(username=username).first():
            flash("Username already exists.")
        elif User.query.filter_by(email=email).first():
            flash("Email already registered.")
        else:
            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
            )
            db.session.add(user)
            db.session.commit()
            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))

    return render_template("register.html")


# User login
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html")
    
# Protected dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    documents = (
        Document.query.filter_by(owner_id=current_user.id)
        .order_by(Document.uploaded_at.desc())
        .all()
    )
    audit_logs = (
        AuditLog.query.filter_by(owner_id=current_user.id)
        .order_by(AuditLog.created_at.desc())
        .limit(10)
        .all()
    )
    category_counts = {}
    for document in documents:
        category_counts[document.category] = category_counts.get(document.category, 0) + 1
    categories = [
        {"name": name, "count": count}
        for name, count in sorted(category_counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    risk_counts = {
        "Low": sum(document.risk_score < 25 for document in documents),
        "Moderate": sum(25 <= document.risk_score < 60 for document in documents),
        "High": sum(document.risk_score >= 60 for document in documents),
    }
    return render_template(
        "dashboard.html",
        documents=documents,
        audit_logs=audit_logs,
        categories=categories,
        max_category_count=max((item["count"] for item in categories), default=1),
        risk_counts=risk_counts,
        total_size=sum(document.file_size for document in documents),
        sensitive_documents=sum(
            sum(document.sensitive_counts.values()) > 0 for document in documents
        ),
        high_risk_documents=risk_counts["High"],
    )


@app.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    uploaded_file = request.files.get("document")
    if uploaded_file is None or not uploaded_file.filename:
        flash("Choose a document to upload.", "error")
        return redirect(url_for("dashboard"))

    original_name = secure_filename(uploaded_file.filename)
    extension = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
    if not original_name or extension not in ALLOWED_EXTENSIONS:
        flash("Supported formats are TXT, Markdown, and CSV.", "error")
        return redirect(url_for("dashboard"))

    content = uploaded_file.read(MAX_FILE_SIZE + 1)
    if len(content) > MAX_FILE_SIZE:
        flash("Files must be 5 MB or smaller.", "error")
        return redirect(url_for("dashboard"))
    if not content:
        flash("The selected file is empty.", "error")
        return redirect(url_for("dashboard"))
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        flash("This file is not valid UTF-8 text and could not be analyzed.", "error")
        return redirect(url_for("dashboard"))

    analysis = analyze_text(text)
    storage_name = f"{uuid.uuid4().hex}.{extension}"
    storage_path = Path(app.config["UPLOAD_FOLDER"]) / storage_name
    storage_path.write_bytes(content)
    document = Document(
        owner_id=current_user.id,
        original_name=original_name,
        storage_name=storage_name,
        file_size=len(content),
        **analysis,
    )
    db.session.add(document)
    db.session.flush()
    record_activity("Uploaded", f"Uploaded {original_name}", document.id)
    db.session.commit()
    flash(f"{original_name} uploaded and analyzed locally.", "success")
    return redirect(url_for("dashboard"))


@app.route("/documents/<int:document_id>/analyze", methods=["POST"])
@login_required
def reanalyze_document(document_id):
    document = Document.query.filter_by(id=document_id, owner_id=current_user.id).first_or_404()
    file_path = Path(app.config["UPLOAD_FOLDER"]) / document.storage_name
    try:
        text = file_path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        flash("The stored text file could not be read.", "error")
        return redirect(url_for("dashboard"))
    for key, value in analyze_text(text).items():
        setattr(document, key, value)
    document.analyzed_at = datetime.utcnow()
    record_activity("Analyzed", f"Re-analyzed {document.original_name}", document.id)
    db.session.commit()
    flash(f"Analysis refreshed for {document.original_name}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    document = Document.query.filter_by(id=document_id, owner_id=current_user.id).first_or_404()
    record_activity("Downloaded", f"Downloaded {document.original_name}", document.id)
    db.session.commit()
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document.storage_name,
        as_attachment=True,
        download_name=document.original_name,
    )


@app.route("/documents/<int:document_id>/delete", methods=["POST"])
@login_required
def delete_document(document_id):
    document = Document.query.filter_by(id=document_id, owner_id=current_user.id).first_or_404()
    original_name = document.original_name
    file_path = Path(app.config["UPLOAD_FOLDER"]) / document.storage_name
    try:
        file_path.unlink(missing_ok=True)
    except OSError:
        flash("The file could not be removed from disk; the record was retained.", "error")
        return redirect(url_for("dashboard"))
    db.session.delete(document)
    record_activity("Deleted", f"Deleted {original_name}")
    db.session.commit()
    flash(f"{original_name} was deleted.", "success")
    return redirect(url_for("dashboard"))


# User logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have logged out successfully.")
    return redirect(url_for("home"))


# Create database tables
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)