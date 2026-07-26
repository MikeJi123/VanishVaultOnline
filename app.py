#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import os
import secrets
import sqlite3
import sys
import time
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
FILE_DIR = DATA_DIR / "files"
DB_PATH = DATA_DIR / "vanishvault.db"

KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
MAX_UPLOAD_BYTES = 12 * 1024 * 1024


def init_db() -> None:
    FILE_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS shares (
                id TEXT PRIMARY KEY,
                sender_token TEXT NOT NULL,
                filename TEXT NOT NULL,
                mime TEXT NOT NULL,
                salt TEXT NOT NULL,
                nonce TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                opened_at INTEGER,
                opened_action TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                size INTEGER NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                share_id TEXT NOT NULL,
                event TEXT NOT NULL,
                detail TEXT,
                created_at INTEGER NOT NULL
            )
            """
        )


def db_connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def derive_key(password: str, salt: bytes) -> bytes:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_LEN,
        maxmem=64 * 1024 * 1024,
    )


def expiry_from_hours(hours: int) -> int | None:
    if hours <= 0:
        return None
    return int((datetime.now() + timedelta(hours=hours)).timestamp())


def format_time(ts: int | None) -> str:
    if ts is None:
        return "Never"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def clean_filename(name: str) -> str:
    cleaned = Path(name.replace("\\", "/")).name.strip()
    return cleaned or "shared-file"


def safe_mime(filename: str, supplied: str | None) -> str:
    guessed = mimetypes.guess_type(filename)[0]
    return supplied or guessed or "application/octet-stream"


def preview_supported(filename: str, mime: str) -> bool:
    lower_name = filename.lower()
    return (
        mime.startswith("image/")
        or mime == "application/pdf"
        or mime.startswith("text/")
        or lower_name.endswith((".txt", ".md", ".csv", ".json", ".py", ".js", ".html", ".css"))
    )


def associated_data(share_id: str, filename: str, mime: str, created_at: int, expires_at: int | None, mode: str) -> bytes:
    return json.dumps(
        {
            "id": share_id,
            "filename": filename,
            "mime": mime,
            "created_at": created_at,
            "expires_at": expires_at,
            "mode": mode,
        },
        sort_keys=True,
    ).encode("utf-8")


def audit(share_id: str, event: str, detail: str | None = None) -> None:
    with db_connect() as db:
        db.execute(
            "INSERT INTO audit (share_id, event, detail, created_at) VALUES (?, ?, ?, ?)",
            (share_id, event, detail, int(time.time())),
        )


def create_share(file_bytes: bytes, filename: str, mime: str | None, password: str, expiry_hours: int, mode: str) -> dict:
    if not file_bytes:
        raise ValueError("Choose a non-empty file.")
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise ValueError("File is too large for this prototype.")
    if mode not in {"preview", "download", "either"}:
        raise ValueError("Invalid access mode.")

    share_id = secrets.token_urlsafe(12)
    sender_token = secrets.token_urlsafe(18)
    filename = clean_filename(filename)
    mime = safe_mime(filename, mime)
    created_at = int(time.time())
    expires_at = expiry_from_hours(expiry_hours)
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(
        nonce,
        file_bytes,
        associated_data(share_id, filename, mime, created_at, expires_at, mode),
    )
    (FILE_DIR / f"{share_id}.bin").write_bytes(ciphertext)

    with db_connect() as db:
        db.execute(
            """
            INSERT INTO shares
            (id, sender_token, filename, mime, salt, nonce, created_at, expires_at,
             mode, status, failed_attempts, size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 0, ?)
            """,
            (share_id, sender_token, filename, mime, b64(salt), b64(nonce), created_at, expires_at, mode, len(file_bytes)),
        )
    audit(share_id, "created", f"expires={format_time(expires_at)}")
    return {"id": share_id, "sender_token": sender_token}


def get_share(share_id: str) -> sqlite3.Row | None:
    with db_connect() as db:
        return db.execute("SELECT * FROM shares WHERE id = ?", (share_id,)).fetchone()


def get_audit(share_id: str) -> list[dict]:
    with db_connect() as db:
        rows = db.execute(
            "SELECT event, detail, created_at FROM audit WHERE share_id = ? ORDER BY id DESC",
            (share_id,),
        ).fetchall()
    return [{"event": r["event"], "detail": r["detail"], "created_at": format_time(r["created_at"])} for r in rows]


def share_public_status(row: sqlite3.Row) -> dict:
    expired = row["expires_at"] is not None and int(time.time()) > row["expires_at"]
    status = "expired" if row["status"] == "active" and expired else row["status"]
    return {
        "id": row["id"],
        "filename": row["filename"],
        "mime": row["mime"],
        "size": row["size"],
        "mode": row["mode"],
        "status": status,
        "created_at": format_time(row["created_at"]),
        "expires_at": format_time(row["expires_at"]),
        "opened_at": format_time(row["opened_at"]) if row["opened_at"] else None,
        "opened_action": row["opened_action"],
        "failed_attempts": row["failed_attempts"],
    }


def unlock_share(share_id: str, password: str, action: str) -> dict:
    if action not in {"preview", "download"}:
        raise ValueError("Invalid action.")
    row = get_share(share_id)
    if row is None:
        raise ValueError("Share not found.")
    if row["mode"] != "either" and row["mode"] != action:
        raise ValueError("This action is not allowed for this share.")
    if action == "preview" and not preview_supported(row["filename"], row["mime"]):
        raise ValueError("Preview is not supported for this file type.")
    if row["status"] == "revoked":
        raise ValueError("This share has been revoked.")
    if row["status"] in {"opened", "downloaded"}:
        raise ValueError("This file has already vanished.")
    if row["expires_at"] is not None and int(time.time()) > row["expires_at"]:
        with db_connect() as db:
            db.execute("UPDATE shares SET status = 'expired' WHERE id = ? AND status = 'active'", (share_id,))
        audit(share_id, "expired", "open blocked")
        raise ValueError("This share has expired.")

    encrypted_path = FILE_DIR / f"{share_id}.bin"
    if not encrypted_path.exists():
        raise ValueError("Encrypted file is missing.")

    try:
        key = derive_key(password, unb64(row["salt"]))
        plaintext = AESGCM(key).decrypt(
            unb64(row["nonce"]),
            encrypted_path.read_bytes(),
            associated_data(row["id"], row["filename"], row["mime"], row["created_at"], row["expires_at"], row["mode"]),
        )
    except (InvalidTag, ValueError) as exc:
        with db_connect() as db:
            db.execute("UPDATE shares SET failed_attempts = failed_attempts + 1 WHERE id = ?", (share_id,))
        audit(share_id, "failed_unlock", action)
        if isinstance(exc, InvalidTag):
            raise ValueError("Wrong password or modified file.") from exc
        raise

    status = "opened" if action == "preview" else "downloaded"
    with db_connect() as db:
        db.execute(
            "UPDATE shares SET status = ?, opened_at = ?, opened_action = ? WHERE id = ?",
            (status, int(time.time()), action, share_id),
        )
    audit(share_id, status, "access burned")
    encrypted_path.unlink(missing_ok=True)
    return {
        "filename": row["filename"],
        "mime": row["mime"],
        "content_b64": b64(plaintext),
        "status": status,
    }


def revoke_share(share_id: str, token: str) -> dict:
    row = get_share(share_id)
    if row is None or row["sender_token"] != token:
        raise ValueError("Invalid dashboard link.")
    if row["status"] == "active":
        with db_connect() as db:
            db.execute("UPDATE shares SET status = 'revoked' WHERE id = ?", (share_id,))
        (FILE_DIR / f"{share_id}.bin").unlink(missing_ok=True)
        audit(share_id, "revoked", "sender")
    return {"ok": True}


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path in {"/", "/index.html"} or path.startswith("/s/") or path.startswith("/d/"):
            self.send_file(STATIC_DIR / "index.html", "text/html")
            return
        if path.startswith("/static/"):
            target = STATIC_DIR / path.removeprefix("/static/")
            self.send_file(target, mimetypes.guess_type(target.name)[0] or "application/octet-stream")
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/api/create":
                data = self.read_json()
                result = create_share(
                    unb64(data["file_b64"]),
                    data["filename"],
                    data.get("mime"),
                    data["password"],
                    int(data.get("expiry_hours", 24)),
                    data.get("mode", "either"),
                )
                origin = self.origin()
                self.send_json(
                    {
                        "share_url": f"{origin}/s/{result['id']}",
                        "dashboard_url": f"{origin}/d/{result['id']}/{result['sender_token']}",
                    }
                )
                return
            if parsed.path == "/api/open":
                data = self.read_json()
                self.send_json(unlock_share(data["id"], data["password"], data["action"]))
                return
            if parsed.path == "/api/status":
                data = self.read_json()
                row = get_share(data["id"])
                if row is None:
                    raise ValueError("Share not found.")
                result = share_public_status(row)
                if data.get("sender_token") == row["sender_token"]:
                    result["audit"] = get_audit(data["id"])
                    result["is_sender"] = True
                self.send_json(result)
                return
            if parsed.path == "/api/revoke":
                data = self.read_json()
                self.send_json(revoke_share(data["id"], data["sender_token"]))
                return
            self.send_error(HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self.send_json({"error": str(exc)}, status=400)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_UPLOAD_BYTES * 2:
            raise ValueError("Request is too large.")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def send_file(self, path: Path, mime: str) -> None:
        if not path.is_file() or not path.resolve().is_relative_to(BASE_DIR):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def origin(self) -> str:
        host = self.headers.get("Host", "127.0.0.1:8787")
        return f"http://{host}"

    def log_message(self, format: str, *args) -> None:
        return


def main() -> None:
    init_db()
    port = int(os.environ.get("VANISHVAULT_PORT", "8787"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"VanishVault Online running at http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
