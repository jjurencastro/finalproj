import base64
import hashlib
import hmac
import os
import secrets
import threading
import uuid
from datetime import datetime
from io import BytesIO
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import boto3
import psycopg
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from werkzeug.security import check_password_hash, generate_password_hash

# Secure File Sharing System (Flask):
# - Authenticated users upload/download files.
# - Files are encrypted before object storage.
# - Integrity is verified before download is returned.

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    # The app cannot run without a database connection string.
    raise RuntimeError("DATABASE_URL is required (Railway Postgres connection URL).")

S3_BUCKET = os.environ.get("S3_BUCKET")
if not S3_BUCKET:
    # The app cannot upload/download files without a storage bucket.
    raise RuntimeError("S3_BUCKET is required for encrypted object storage.")

S3_REGION = os.environ.get("S3_REGION", "us-east-1")
S3_ENDPOINT_URL_RAW = os.environ.get("S3_ENDPOINT_URL")
S3_ACCESS_KEY_ID = os.environ.get("S3_ACCESS_KEY_ID")
S3_SECRET_ACCESS_KEY = os.environ.get("S3_SECRET_ACCESS_KEY")
S3_SESSION_TOKEN = os.environ.get("S3_SESSION_TOKEN")
S3_FORCE_PATH_STYLE = os.environ.get("S3_FORCE_PATH_STYLE", "0") == "1"
DB_CONNECT_TIMEOUT = int(os.environ.get("DB_CONNECT_TIMEOUT", "5"))

_db_bootstrap_lock = threading.Lock()
_db_bootstrapped = False


def normalize_s3_endpoint(raw_endpoint: str | None, bucket: str) -> str | None:
    # Cleans provider endpoint so boto3 can connect reliably.
    if not raw_endpoint:
        return None

    value = raw_endpoint.strip().strip('"').strip("'")
    if not value or value.lower() in {"none", "null"}:
        return None

    if "://" not in value:
        value = f"https://{value}"

    parsed = urlsplit(value)
    if not parsed.netloc:
        return value

    path = (parsed.path or "").strip("/")
    if path and path == bucket:
        # Common misconfiguration: endpoint copied as https://host/bucket.
        path = ""

    normalized_path = f"/{path}" if path else ""
    return urlunsplit((parsed.scheme, parsed.netloc, normalized_path, "", ""))


def load_master_key() -> bytes:
    """Load a 32-byte master key from env var FILE_MASTER_KEY."""
    encoded_key = os.environ.get("FILE_MASTER_KEY")
    if not encoded_key:
        raise RuntimeError(
            "FILE_MASTER_KEY is missing. Set it to a base64-encoded 32-byte key."
        )

    # Accept a few common representations to reduce deployment misconfiguration:
    # - URL-safe base64 (recommended)
    # - Standard base64
    # - 64-char hex string
    raw_value = encoded_key.strip()

    # Railway/UI copy-paste sometimes includes wrapping quotes.
    if (
        len(raw_value) >= 2
        and raw_value[0] == raw_value[-1]
        and raw_value[0] in {'"', "'"}
    ):
        raw_value = raw_value[1:-1].strip()

    # Accept Python-style bytes literal wrappers like b'...'.
    if raw_value.startswith("b'") and raw_value.endswith("'"):
        raw_value = raw_value[2:-1].strip()
    elif raw_value.startswith('b"') and raw_value.endswith('"'):
        raw_value = raw_value[2:-1].strip()

    # Try hex first for explicitness and easy debugging.
    try:
        if len(raw_value) == 64 and all(c in "0123456789abcdefABCDEF" for c in raw_value):
            key = bytes.fromhex(raw_value)
        else:
            normalized = raw_value.replace("\n", "").replace("\r", "").replace(" ", "")
            padding = "=" * ((4 - len(normalized) % 4) % 4)
            key = base64.urlsafe_b64decode((normalized + padding).encode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive
        raise RuntimeError(
            "FILE_MASTER_KEY is invalid. Use urlsafe base64 for 32 bytes or 64-char hex."
        ) from exc

    if len(key) != 32:
        raise RuntimeError(
            f"FILE_MASTER_KEY must decode to exactly 32 bytes (got {len(key)} bytes)"
        )

    return key


MASTER_KEY = load_master_key()
S3_ENDPOINT_URL = normalize_s3_endpoint(S3_ENDPOINT_URL_RAW, S3_BUCKET)

s3_client_kwargs: dict[str, Any] = {
    "endpoint_url": S3_ENDPOINT_URL,
    "aws_access_key_id": S3_ACCESS_KEY_ID,
    "aws_secret_access_key": S3_SECRET_ACCESS_KEY,
    "region_name": S3_REGION,
}
if S3_SESSION_TOKEN:
    s3_client_kwargs["aws_session_token"] = S3_SESSION_TOKEN
if S3_FORCE_PATH_STYLE:
    s3_client_kwargs["config"] = Config(s3={"addressing_style": "path"})

s3_client = boto3.client("s3", **s3_client_kwargs)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("APP_SECRET_KEY", secrets.token_hex(32)),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)

# Data model summary for demo discussion:
# - users table: account credentials.
# - files table: encrypted file metadata (ciphertext is in object storage).


def get_db() -> psycopg.Connection:
    # Reuse one DB connection per request for better performance.
    ensure_db_ready()
    if "db" not in g:
        g.db = psycopg.connect(
            DATABASE_URL,
            row_factory=dict_row,
            connect_timeout=DB_CONNECT_TIMEOUT,
        )
    return g.db


@app.teardown_appcontext
def close_db(_: object) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    # Creates tables on first run so setup is automatic.
    db = psycopg.connect(DATABASE_URL, connect_timeout=DB_CONNECT_TIMEOUT)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id BIGSERIAL PRIMARY KEY,
            owner_id BIGINT NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            salt BYTEA NOT NULL,
            nonce BYTEA NOT NULL,
            sha256 TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        )
        """
    )
    db.commit()
    db.close()


def ensure_db_ready() -> None:
    global _db_bootstrapped

    if _db_bootstrapped:
        return

    with _db_bootstrap_lock:
        if _db_bootstrapped:
            return
        try:
            init_db()
            # Mark as ready so future requests skip setup checks.
            _db_bootstrapped = True
        except Exception as exc:
            raise RuntimeError(
                "Database is unavailable. Check DATABASE_URL/SSL settings and Postgres status."
            ) from exc


def derive_file_key(owner_id: int, salt: bytes) -> bytes:
    # Per-file AES key derivation from one master key + random salt.
    # Owner ID is mixed into HKDF context so keys are user-scoped.
    info = f"secure-share-owner:{owner_id}".encode("utf-8")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(MASTER_KEY)


def encrypt_content(owner_id: int, data: bytes) -> tuple[bytes, bytes, bytes]:
    # AES-256-GCM encryption path (confidentiality + tamper detection).
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_file_key(owner_id, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return salt, nonce, ciphertext


def decrypt_content(owner_id: int, salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    # Decryption succeeds only if GCM authentication tag is valid.
    key = derive_file_key(owner_id, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def login_required() -> int:
    # Simple guard: blocked users are redirected to log in.
    user_id = session.get("user_id")
    if user_id is None:
        abort(401)
    return int(user_id)


def current_user() -> dict[str, Any] | None:
    # Used by templates to display the signed-in username.
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return get_db().execute("SELECT id, username FROM users WHERE id = %s", (user_id,)).fetchone()


def store_ciphertext(stored_name: str, ciphertext: bytes) -> None:
    try:
        # Save encrypted bytes only (never plaintext) to object storage.
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=stored_name,
            Body=ciphertext,
            ContentType="application/octet-stream",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        message = exc.response.get("Error", {}).get("Message", "Unknown error")
        raise RuntimeError(f"Object storage write failed ({code}): {message}") from exc
    except BotoCoreError as exc:
        raise RuntimeError(f"Object storage write failed: {exc}") from exc


def load_ciphertext(stored_name: str) -> bytes | None:
    try:
        # Read encrypted bytes back from object storage for download.
        response = s3_client.get_object(Bucket=S3_BUCKET, Key=stored_name)
        return response["Body"].read()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"NoSuchKey", "404"}:
            return None
        message = exc.response.get("Error", {}).get("Message", "Unknown error")
        raise RuntimeError(f"Object storage read failed ({code}): {message}") from exc
    except BotoCoreError as exc:
        raise RuntimeError(f"Object storage read failed: {exc}") from exc


def storage_error_hint(error_text: str) -> str:
    text = error_text.lower()
    if "nosuchbucket" in text:
        return "Storage bucket not found. Check S3_BUCKET."
    if "accessdenied" in text:
        return (
            "Storage access denied. Ensure credentials include s3:PutObject and s3:GetObject "
            f"for bucket '{S3_BUCKET}' (and s3:ListBucket for diagnostics)."
        )
    if "invalidaccesskeyid" in text or "signaturedoesnotmatch" in text:
        return "Storage credentials/signing failed. Check S3 keys, region, and endpoint."
    if "could not connect" in text or "endpoint" in text:
        endpoint = S3_ENDPOINT_URL or "AWS default endpoint"
        return f"Storage endpoint unreachable. Check S3_ENDPOINT_URL/network. Current endpoint: {endpoint}"
    return "Storage request failed. Check S3 endpoint, region, bucket, and credentials."


def ensure_csrf_token() -> str:
    # Creates anti-CSRF token once per session to block forged form submits.
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf() -> bool:
    # Safe token compare avoids timing attacks.
    expected = session.get("csrf_token", "")
    provided = request.form.get("csrf_token", "")
    return bool(expected) and hmac.compare_digest(expected, provided)


@app.context_processor
def inject_csrf_token() -> dict[str, object]:
    return {"csrf_token": ensure_csrf_token(), "current_user": current_user()}


@app.route("/")
def index() -> str:
    # Landing route sends users to login or dashboard.
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/healthz")
def healthz() -> tuple[dict[str, str], int]:
    # Health endpoint used by deployment platform checks.
    try:
        ensure_db_ready()
    except RuntimeError as exc:
        return {"status": "error", "detail": str(exc)}, 503
    return {"status": "ok"}, 200


@app.route("/register", methods=["GET", "POST"])
def register() -> str:
    # Demo step: account creation with hashed password storage.
    if request.method == "POST":
        # CSRF validation ensures the form came from our site.
        if not validate_csrf():
            abort(400, "CSRF validation failed")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(password) < 8:
            flash("Username must be >= 3 chars and password >= 8 chars.", "error")
            return render_template("register.html")

        # Password is hashed so raw password is never stored.
        password_hash = generate_password_hash(password)

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (%s, %s, %s)",
                (username, password_hash, datetime.utcnow().isoformat()),
            )
            db.commit()
        except UniqueViolation:
            db.rollback()
            flash("Username already exists.", "error")
            return render_template("register.html")

        flash("Registration successful. Please log in.", "ok")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login() -> str:
    # Demo step: login verifies password hash and starts secure session.
    if request.method == "POST":
        # CSRF validation ensures the form came from our site.
        if not validate_csrf():
            abort(400, "CSRF validation failed")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        row = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = %s", (username,)
        ).fetchone()
        if row is None or not check_password_hash(row["password_hash"], password):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        # Clear old session data to prevent session fixation.
        session.clear()
        # Store logged-in user ID in session cookie context.
        session["user_id"] = int(row["id"])
        # Create fresh CSRF token for all protected forms.
        session["csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout() -> str:
    # Require CSRF token for logout form too.
    if not validate_csrf():
        abort(400, "CSRF validation failed")
    # Remove login state.
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard() -> str:
    # Show only files owned by the currently logged-in user.
    user_id = login_required()
    files = get_db().execute(
        """
        SELECT id, original_name, uploaded_at
        FROM files
        WHERE owner_id = %s
        ORDER BY id DESC
        """,
        (user_id,),
    ).fetchall()
    return render_template("dashboard.html", files=files)


@app.route("/upload", methods=["POST"])
def upload() -> str:
    # Demo step: upload flow shown in the final project presentation.
    # 1) Confirm user is logged in.
    user_id = login_required()

    # 2) Validate anti-CSRF token.
    if not validate_csrf():
        abort(400, "CSRF validation failed")

    # 3) Read file from submitted form.
    uploaded = request.files.get("file")
    if uploaded is None or uploaded.filename is None or uploaded.filename.strip() == "":
        flash("Please choose a file to upload.", "error")
        return redirect(url_for("dashboard"))

    # 4) Get raw file bytes in memory.
    plaintext = uploaded.read()
    if not plaintext:
        flash("Empty files are not allowed.", "error")
        return redirect(url_for("dashboard"))

    # 5) Enforce max upload size.
    if len(plaintext) > app.config["MAX_CONTENT_LENGTH"]:
        flash("File too large.", "error")
        return redirect(url_for("dashboard"))

    # Integrity checkpoint 1: keep SHA-256 of original plaintext.
    sha256_hex = hashlib.sha256(plaintext).hexdigest()

    # Core security operation: encrypt before sending to object storage.
    salt, nonce, ciphertext = encrypt_content(user_id, plaintext)

    # 6) Use random storage filename so original name is not exposed in bucket key.
    stored_name = f"{uuid.uuid4().hex}.bin"
    try:
        # 7) Upload encrypted content to object storage.
        store_ciphertext(stored_name, ciphertext)
    except RuntimeError as exc:
        app.logger.exception("Upload object storage failure: %s", exc)
        flash(storage_error_hint(str(exc)), "error")
        return redirect(url_for("dashboard"))

    # 8) Save metadata needed for future download/decryption.
    get_db().execute(
        """
        INSERT INTO files (owner_id, original_name, stored_name, salt, nonce, sha256, uploaded_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            user_id,
            uploaded.filename,
            stored_name,
            salt,
            nonce,
            sha256_hex,
            datetime.utcnow().isoformat(),
        ),
    )
    get_db().commit()

    # 9) Show success to user and return to dashboard.
    flash("File uploaded and encrypted successfully.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/download/<int:file_id>")
def download(file_id: int):
    # Demo step: download flow with decryption and integrity verification.
    # 1) Confirm user is logged in.
    user_id = login_required()

    # 2) Load only if this file belongs to the current user.
    row = get_db().execute(
        """
        SELECT id, original_name, stored_name, salt, nonce, sha256
        FROM files
        WHERE id = %s AND owner_id = %s
        """,
        (file_id, user_id),
    ).fetchone()
    if row is None:
        abort(404)

    try:
        # 3) Fetch encrypted bytes from object storage.
        ciphertext = load_ciphertext(row["stored_name"])
    except RuntimeError as exc:
        app.logger.exception("Download object storage failure: %s", exc)
        abort(503, storage_error_hint(str(exc)))

    if ciphertext is None:
        abort(404)

    try:
        # Core security operation: decrypt object bytes back to plaintext.
        # 4) Unlock file bytes using derived key + saved nonce/salt.
        plaintext = decrypt_content(user_id, row["salt"], row["nonce"], ciphertext)
    except InvalidTag:
        # AES-GCM tag failure means ciphertext was modified or wrong key was used.
        abort(409, "Integrity verification failed: encrypted data was tampered with")

    # Integrity checkpoint 2: compare plaintext hash with stored hash.
    # 5) Verify downloaded plaintext fingerprint matches original upload.
    downloaded_hash = hashlib.sha256(plaintext).hexdigest()
    if not hmac.compare_digest(downloaded_hash, row["sha256"]):
        abort(409, "Integrity verification failed: hash mismatch")

    # 6) Return decrypted file to user browser.
    return send_file(
        BytesIO(plaintext),
        as_attachment=True,
        download_name=row["original_name"],
        mimetype="application/octet-stream",
    )


@app.errorhandler(401)
def unauthorized(_: object):
    flash("Please log in first.", "error")
    return redirect(url_for("login"))


@app.errorhandler(413)
def payload_too_large(_: object):
    flash("File exceeds max size (16MB).", "error")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
