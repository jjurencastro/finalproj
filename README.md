# Secure File Sharing System

This project is a simple secure file-sharing web application built with Flask.
It allows authenticated users to upload and download files while enforcing:

1. Confidentiality
2. Integrity
3. Authentication

## Security Design

### 1) Confidentiality
- Files are encrypted before being stored in object storage.
- Encryption uses AES-256-GCM (`cryptography` library), which provides strong modern encryption.
- Raw uploaded files are never stored in plaintext.
- A required environment variable, `FILE_MASTER_KEY`, supplies a 32-byte secret used for key derivation.

### 2) Integrity
- AES-GCM authentication tags detect ciphertext tampering.
- A SHA-256 hash of the original plaintext is stored in metadata.
- On download, the file is decrypted and hashed again.
- If authentication tag or hash verification fails, the download is rejected.

### 3) Authentication
- Users must register and log in with username/password.
- Passwords are stored as secure hashes (not plaintext).
- Only the owner of a file can download that file.
- Session cookies are hardened with `HttpOnly` and `SameSite=Lax`.

## Project Structure

```
.
├── app.py
├── requirements.txt
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
└── README.md
```

Runtime-generated:
- Metadata in PostgreSQL (`DATABASE_URL`)
- Encrypted blobs in S3-compatible storage (`S3_BUCKET`)

## Setup and Run

1. Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Generate keys and export environment variables:

```bash
export APP_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export FILE_MASTER_KEY="$(python3 -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
export DATABASE_URL="postgresql://USER:PASSWORD@HOST:PORT/DBNAME"
export S3_BUCKET="your-bucket-name"
export S3_REGION="us-east-1"
export S3_ENDPOINT_URL="https://s3.amazonaws.com"
export S3_ACCESS_KEY_ID="your-access-key"
export S3_SECRET_ACCESS_KEY="your-secret-key"
```

Optional (recommended in HTTPS deployments):

```bash
export COOKIE_SECURE=1
```

4. Start the app:

```bash
python3 app.py
```

5. Open in browser:

```
http://localhost:5000
```

## How to Use

1. Register a user account.
2. Log in.
3. Upload a file from the dashboard (file is encrypted and stored).
4. Download a file (it is decrypted only after integrity verification).

## Notes and Limitations

- This is an educational, minimal implementation.
- Deploy behind HTTPS in production.
- The app now uses PostgreSQL and S3-compatible storage, which are suitable for Railway production deployment.
- Add audit logging, account lockout/rate limiting, and optional MFA for stronger production security.

## Railway Deployment Notes

1. Add Railway PostgreSQL and copy its `DATABASE_URL` into service variables.
2. Configure S3-compatible storage variables (`S3_BUCKET`, `S3_REGION`, `S3_ENDPOINT_URL`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`).
	- If your provider requires path-style S3 URLs (common for MinIO/LocalStack/some gateways), set `S3_FORCE_PATH_STYLE=1`.
3. Set `APP_SECRET_KEY`, `FILE_MASTER_KEY`, and `COOKIE_SECURE=1`.
	 - Generate `FILE_MASTER_KEY` as URL-safe base64 (recommended):
		 `python3 -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'`
	 - The app also accepts a 64-char hex key:
		 `python3 -c 'import secrets; print(secrets.token_hex(32))'`
	 - Paste only the raw key value in Railway (no `export ...=`, no surrounding quotes).
4. Optional: set `DB_CONNECT_TIMEOUT` (seconds, default `5`) if you need to tune DB connect behavior.
5. Optional: set the Railway health check path to `/healthz`.
6. Redeploy. Tables are auto-created when the app first reaches the database.

If upload/download fails, check deploy logs for `Upload object storage failure` or `Download object storage failure` to see the exact provider error code/message.
The dashboard and download errors also show a short actionable hint based on provider error codes (bucket, credentials, endpoint, or permissions).
