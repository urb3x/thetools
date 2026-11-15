# FolderVault

An advanced Tkinter desktop tool to encrypt, password-protect, verify, and decrypt folders using trusted, industry-standard authenticated encryption.

## Cryptographic Design

- **Cipher:** Chunked **AES-256-GCM** (Authenticated Encryption with Associated Data, 4 MiB chunks). Each chunk uses a unique 96-bit nonce derived from a random base nonce and binds the 64-byte vault header, chunk index, and final-chunk flag in the AEAD Associated Data (AAD) to prevent tampering, reordering, or truncation.
- **Key Derivation (KDF):**
  - **Argon2id** (default, OWASP recommended: `t=3`, `m=64 MiB`, `p=4`, 16-byte random salt)
  - **PBKDF2-HMAC-SHA256** (`600,000` iterations, 16-byte random salt)
- **Container Format (`.pfvault`):** Self-describing 64-byte binary header + authenticated encrypted ZIP64 payload, with Zip-Slip path traversal protection on extraction.

## Features

- **Modern Dark / Light Theme** with Windows High-DPI awareness
- **Encrypt Folder Tab:** Folder scanner (file/subfolder count & total size), password strength meter with entropy estimation, cryptographically random password generator, KDF & compression selectors, and optional confirmed original-folder deletion
- **Decrypt / Verify Tab:** Live `.pfvault` header inspector, integrity-only verification (without extracting), and safe extraction
- **Non-blocking UI:** Background worker thread with real-time progress bar, cancellation support, and color-coded activity log

## Requirements

- Python 3.10+ (with standard `tkinter`)
- `cryptography` (`pip install cryptography`)

## Usage

Run the application:

```powershell
python main.py
```

Run the unit tests:

```powershell
python -m unittest discover -s tests -v
```
