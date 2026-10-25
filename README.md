TrustVault – Secure Document Management Platform

Project Overview

TrustVault is a Flask-based web application designed to manage documents securely. It allows users to upload, analyze, download, and delete documents. The application also provides risk scoring and audit activity tracking.

Features

- User registration and login
- Document upload and management
- Rule-based sensitive information detection
- Document risk score and risk classification
- Document re-analysis
- Secure document download and deletion
- Audit activity tracking

Technology Stack

- Python
- Flask
- Flask-SQLAlchemy
- Flask-Login
- SQLite
- HTML

How to Run the Project

1. Clone the repository:
   "git clone https://github.com/divya-1118/TrustVault.git"

2. Open the project folder:
   "cd TrustVault"

3. Create and activate a virtual environment:
   "python -m venv venv"

4. Install dependencies:
   "pip install -r requirements.txt"

5. Run the application using the entry point defined in "app.py". For example, if the file has a standard Flask startup block, run:
   "python app.py"

6. Open the local URL shown in the terminal, usually "http://127.0.0.1:5000".

Security Notes

The application uses login functionality, input validation, and audit logging. Sensitive information detection is rule-based and may not identify every possible sensitive value. This project is a prototype and requires further security testing before production use.

Repository

https://github.com/divya-1118/TrustVault

Current Limitations

- Detection depends on predefined rules.
- Production deployment requires suitable persistent storage and secure configuration.
- Additional authorization and security testing may be needed.