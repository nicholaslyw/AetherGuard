# AetherGuard

A secure file-sharing platform using end-to-end hybrid encryption. Files are encrypted on the client before being sent to the server — the server never sees plaintext data or encryption keys.

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- Python 3.10+

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/nicholaslyw/AetherGuard.git
cd AetherGuard
```

### 2. Start the server

The server runs in Docker. From the repo root:

```bash
docker-compose up server
```

The server will be available at `http://localhost:5000`. Leave this terminal running.

### 3. Set up the client

Open a **new terminal** and navigate to the client directory:

```bash
cd client
```

Create and activate a virtual environment:

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create the local directories for keys and downloads:

```bash
mkdir keys
mkdir downloads
```

### 4. Run the client

```bash
python client.py
```

---

## Usage

### CLI Client

When the client starts you will see a menu. If you are not logged in:

```
  1. Register
  2. Login
  3. Exit
```

Once logged in:

```
  1. Upload file
  2. List files
  3. Download file
  4. Grant access
  5. Revoke access
  6. Logout
  7. Exit
```

**Register** — creates an RSA-4096 key pair locally and registers your public key with the server.

**Upload** — encrypts the file locally with AES-256-GCM, then sends only the ciphertext to the server. Optionally share with other users at upload time.

**Download** — fetches the encrypted file and decrypts it locally using your private key. Saved to `client/downloads/`.

**Grant / Revoke** — lets the file owner give or remove access for other registered users. Revoking re-encrypts the file with a fresh key so the removed user's copy is permanently invalidated.

---

### Web UI

AetherGuard includes a browser-based interface for managing file access. It runs as a local server on your machine — all encryption and decryption still happens locally using your key files, so nothing sensitive ever leaves your machine.

#### Setup

Open a new terminal and navigate to the `web_ui` directory:

```bash
cd web_ui
```

Create and activate a virtual environment:

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

#### Run

```bash
python app.py
```

Then open **http://localhost:8080** in your browser.

> The AetherGuard server must already be running (`docker-compose up server`) before starting the Web UI.

#### Features

**Sign in** — use the same username and password you registered with via the CLI. Your local private key file (`client/keys/<username>_private.pem`) must exist on the machine running the Web UI.

**Upload** — select any file and optionally enter a comma-separated list of usernames to share with at upload time. The file is encrypted before it leaves your browser session.

**Download** — click **Download** next to any file you have access to. It is decrypted locally and saved to your browser's downloads folder.

**Manage ACL** *(owners only)* — click the **Manage ACL** button on any file you own to open the access control panel:

- **View** the full list of users who currently have access.
- **Grant** access to a new user by entering their username. The DEK is re-wrapped with their public key automatically.
- **Revoke** a user's access with the **Revoke** button. The file is re-encrypted with a brand-new key and all remaining users receive an updated wrapped key — the removed user's copy is permanently invalidated.

---

## Project Structure

```
AetherGuard/
├── server/
│   ├── app.py            # Flask REST API
│   ├── models.py         # SQLite schema
│   ├── crypto_utils.py   # Password hashing (PBKDF2)
│   ├── requirements.txt
│   └── Dockerfile
├── client/
│   ├── client.py         # CLI interface
│   ├── crypto_utils.py   # Encryption/decryption logic
│   ├── requirements.txt
│   └── Dockerfile
├── web_ui/
│   ├── app.py            # Local Flask proxy (port 8080)
│   ├── requirements.txt
│   └── templates/
│       └── index.html    # Single-page ACL management UI
├── docker-compose.yml
└── README.md
```

---

## Stopping the server

```bash
docker-compose down
```

To also remove stored data (files and database):

```bash
docker-compose down -v
```
