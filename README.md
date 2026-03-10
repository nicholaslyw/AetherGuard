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

Install dependencies:

```bash
pip install -r requirements.txt
```

### 4. Run the client

```bash
python client.py
```

The client will automatically create the `keys/` and `downloads/` directories on first run.

---

## Usage

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

**Grant / Revoke** — lets the file owner give or remove access for other registered users.

---

## Project Structure

```
AetherGuard/
├── server/
│   ├── app.py            # Flask REST API (9 endpoints)
│   ├── models.py         # SQLite schema
│   ├── crypto_utils.py   # Password hashing (PBKDF2)
│   ├── requirements.txt
│   └── Dockerfile
├── client/
│   ├── client.py         # CLI interface
│   ├── crypto_utils.py   # Encryption/decryption logic
│   ├── requirements.txt
│   └── Dockerfile
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
