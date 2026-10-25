TrustVault — Security Threats

1. Unauthorized Document Access

Threat: A user may attempt to access another user's documents.

Mitigation: Require authentication and verify document ownership on every document-related route.

2. Malicious File Uploads

Threat: An attacker may upload an unsafe or excessively large file.

Mitigation: Validate file types, enforce upload size limits, generate safe filenames, and store uploads outside publicly accessible directories.

3. Sensitive Information Exposure

Threat: Uploaded documents may contain personal or confidential information.

Mitigation: Limit access to authorized users, avoid logging document contents, and protect stored files.

4. Cross-Site Request Forgery (CSRF)

Threat: A malicious website may attempt to submit unwanted actions using a logged-in user's session.

Mitigation: Use CSRF protection for state-changing forms and validate requests.

5. Weak Authentication and Sessions

Threat: Weak passwords or improperly protected sessions may allow account compromise.

Mitigation: Use secure password hashing, protect session cookies, and use HTTPS in deployment.

6. Audit Log Tampering

Threat: An attacker may try to alter or erase activity records.

Mitigation: Restrict audit-log access and consider protected, append-only logging for production.