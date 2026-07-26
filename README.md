# VanishVault Online

VanishVault Online is a small local web app for one-time secure file sharing.

## Features

- Password-protected file sharing links
- One-time preview or download
- Expiry time and sender revocation
- Sender dashboard with status and audit events
- Encrypted file storage using scrypt and AES-256-GCM

## Run

```bash
pip install -r requirements.txt
python app.py
```

Then open:

```text
http://127.0.0.1:8787
```

## Submitted Files

- `app.py`
- `requirements.txt`
- `static/index.html`
- `static/styles.css`
- `static/app.js`

## Security Model

Files are encrypted with AES-256-GCM. The password is converted into a key using
scrypt with a random salt. If the password is wrong or the encrypted file is
modified, decryption fails.

This is server-controlled one-time access. The server can stop future access by
burning, expiring, or revoking a share. It cannot erase a plaintext copy after a
recipient has already previewed, downloaded, copied, screenshotted, or recorded
the file.
