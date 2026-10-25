from flask import Flask, request, redirect, url_for, render_template_string, flash
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

app = Flask(__name__)

# Application configuration
app.config["SECRET_KEY"] = "change-this-to-a-long-random-secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///trustvault.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

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

    return render_template_string("""
    <h1>Create TrustVault Account</h1>
    {% for message in get_flashed_messages() %}
        <p>{{ message }}</p>
    {% endfor %}
    <form method="POST">
        <label>Username</label><br>
        <input name="username" required maxlength="80"><br><br>

        <label>Email</label><br>
        <input type="email" name="email" required maxlength="120"><br><br>

        <label>Password (minimum 8 characters)</label><br>
        <input type="password" name="password" required minlength="8"><br><br>

        <button type="submit">Register</button>
    </form>
    <p><a href="{{ url_for('home') }}">Home</a></p>
    <p><a href="{{ url_for('login') }}">Already registered? Login</a></p>
    """)


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

    return render_template_string("""
    <h1>TrustVault Login</h1>
    {% for message in get_flashed_messages() %}
        <p>{{ message }}</p>
    {% endfor %}
    <form method="POST">
        <label>Email</label><br>
        <input type="email" name="email" required><br><br>

        <label>Password</label><br>
        <input type="password" name="password" required><br><br>

        <button type="submit">Login</button>
    </form>
    <p><a href="{{ url_for('home') }}">Home</a></p>
    <p><a href="{{ url_for('register') }}">Create an account</a></p>
    """)


# Protected dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template_string("""
    <h1>TrustVault Dashboard</h1>
    <p>You are logged in as {{ current_user.username }}.</p>
    <p>Email: {{ current_user.email }}</p>
    <p>Document sharing features will be added next.</p>
    <a href="{{ url_for('logout') }}">Logout</a>
    """)


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