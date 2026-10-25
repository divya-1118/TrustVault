from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config["SECRET_KEY"] = "change-this-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///trustvault.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)


@app.route("/")
def home():
    return """
    <h1>Welcome to TrustVault</h1>
    <p>Secure Document Sharing Platform</p>
    <p>Database setup is ready!</p>
    """


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)