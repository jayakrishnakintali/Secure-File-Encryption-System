# Secure File Encryption and Decryption System

A Windows desktop application (Python + Tkinter) that encrypts any file with a
password and decrypts it again. It uses **AES-256-GCM** for encryption and
**Scrypt** for turning the password into a key, both from the trusted
[`cryptography`](https://cryptography.io) library. No home-made cryptography.

> Mini-project - MCA (Cloud Computing and DevOps).

## Main features

- Encrypt and decrypt any file type: PDF, DOCX, TXT, JPG, PNG, ZIP, CSV and other binary files.
- The original file is never changed; the encrypted copy is saved as `<name>.<ext>.enc`.
- Wrong passwords and any modification, corruption or truncation of an encrypted file are detected; no plaintext is produced in that case.
- Existing files are never overwritten without approval.
- Large files are processed in 1 MiB chunks, so they do not have to fit in memory.
- Responsive GUI: the work runs in a background thread with a progress bar.
- Versioned, documented encrypted-file format (see below).
- 40 automated tests (`unittest`).

## Technologies used

| Purpose | Technology |
|---|---|
| Language | Python 3.9+ |
| GUI | Tkinter / ttk with custom styling |
| Cryptography | `cryptography` (AES-256-GCM, Scrypt) |
| Randomness | `os.urandom()` |
| Tests | `unittest` |
| Version control | Git and GitHub |

## Project structure

```
Secure-File-Encryption-System/
├── main.py               GUI (no cryptography inside)
├── crypto_manager.py     encryption, decryption, key derivation, file format
├── requirements.txt
├── README.md
├── .gitignore
└── tests/
    ├── __init__.py
    └── test_crypto_manager.py
```

## Installation on Windows 11

1. Install Python 3.9 or newer from <https://www.python.org/downloads/>.
   Tick **"Add python.exe to PATH"**, and keep **"tcl/tk and IDLE"** selected (it is by default - Tkinter needs it).
2. Open **PowerShell** in the project folder and create a virtual environment:

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

If PowerShell blocks the script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use Command Prompt and `venv\Scripts\activate.bat`.

3. Install the dependency:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Running the application

```powershell
python main.py
```

## Running the automated tests

```powershell
python -m unittest discover -s tests -v
```

The tests only use temporary folders and never touch your own documents.

## How to encrypt a file

1. Open the **Encrypt** page and click **Browse** (or press `Ctrl+O`).
2. Choose a password (at least 8 characters, 12 or more recommended) and type it twice.
3. Click **Encrypt File**. The encrypted copy appears next to the original, e.g. `report.pdf` -> `report.pdf.enc`.

## How to decrypt a file

1. Open the **Decrypt** page and select a `.enc` file made by this application.
2. Enter the password and click **Decrypt File**.
3. The original is restored next to the `.enc` file under its original name. If that name is taken you can save under a new name, pick another location, or explicitly approve overwriting.

## AES-256-GCM and Scrypt in simple words

**AES-256-GCM** is the lock. AES is the standard algorithm that scrambles data using a 256-bit secret key. "GCM" is a mode that also adds a small *authentication tag* to the data. When decrypting, the tag is checked first: if even one bit was changed, or the key is wrong, the check fails and nothing is released.

**Scrypt** makes the key. People choose passwords, not 256-bit keys, so Scrypt converts your password into a proper key. It is deliberately slow and memory-hungry, so an attacker guessing millions of passwords pays a heavy price for every single guess. A random **salt** (stored in the file, not secret) makes sure the same password gives a different key for every file.

**Nonce** - a random value used once per encrypted piece of data so that identical data never encrypts identically.

## Encrypted file format (version 1, magic `SFES`)

All numbers are big-endian.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Magic bytes `SFES` |
| 4 | 1 | Format version (`1`) |
| 5 | 1 | KDF id (`1` = Scrypt) |
| 6 | 1 | Scrypt N as a power of two (default `17`, N = 131072) |
| 7 | 1 | Scrypt r (default `8`) |
| 8 | 1 | Scrypt p (default `1`) |
| 9 | 16 | Random salt |
| 25 | 8 | Random nonce prefix |
| 33 | 4 | Chunk size in bytes (default 1 MiB) |
| 37 | 2 | Length *L* of the original filename |
| 39 | L | Original filename (UTF-8, a name only, never a path) |
| 39+L | ... | Ciphertext chunks, each = encrypted data + 16-byte GCM tag |

- Per-chunk nonce = nonce prefix (8 bytes) + chunk counter (4 bytes).
- Per-chunk AAD (authenticated, not encrypted) = the whole header + one byte (`1` for the last chunk, otherwise `0`).
- Result: changes to the header, reordering of chunks, removing the last chunk(s) or appending data are all detected.
- Plaintext is written to a temporary file and renamed to its final name only after **every** chunk has been verified.

## Security notes and limitations

- **No password recovery.** A forgotten password means the data is gone. This is by design.
- **Password strength decides everything.** Scrypt only slows guessing down. Use a long passphrase (several unrelated words, 12+ characters) and do not reuse it elsewhere.
- **Wrong password and tampering look the same.** AES-GCM cannot tell them apart, so the application says so honestly.
- **Metadata is visible.** The encrypted file reveals that it was made by this application, its approximate size, and its Scrypt settings. The original filename is stored inside the header **unencrypted** (but authenticated).
- **Not protected:** malware or keyloggers on your computer, someone watching you type the password, or the password staying in Python's process memory (Python strings cannot be reliably wiped).
- The original file is not securely erased; deleting it is your decision.
- This is a student project. It has **not** been professionally audited and does not protect against every threat.
- Peak memory use is roughly 128 MiB for Scrypt plus a few MiB for the chunk buffers.

## Uploading to GitHub

1. Create an **empty** public repository named `secure-file-encryption-system` on <https://github.com/new> (do not add a README or .gitignore there).
2. In the project folder run:

```powershell
git init
git add .
git status
git commit -m "Initial commit: Secure File Encryption and Decryption System"
git branch -M main
git remote add origin https://github.com/<your-username>/secure-file-encryption-system.git
git push -u origin main
```

Before committing, run `git status` and make sure no `venv/`, `.enc` files or personal documents are listed. If Git asks who you are, run once:
`git config --global user.name "Your Name"` and `git config --global user.email "you@example.com"`.
