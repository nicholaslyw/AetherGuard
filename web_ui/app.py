"""
AetherGuard Web UI
==================
Local Flask server (port 8080) that acts as a crypto-aware proxy
between the browser and the AetherGuard backend (port 5000).

All RSA/AES operations happen here using the local key files in
../client/keys/, so private keys never leave the machine.

Run:
    python app.py
Then open http://localhost:8080
"""

import base64
import os
import sys

import requests
from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    session,
)

# Reuse crypto_utils from the client package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client"))
from crypto_utils import (  # noqa: E402
    decrypt_file,
    encrypt_file,
    load_private_key,
    load_public_key_from_pem,
    unwrap_dek,
    wrap_dek,
)

app = Flask(__name__)
app.secret_key = os.urandom(32)

SERVER_URL = os.environ.get("AETHERGUARD_SERVER", "http://localhost:5000")
KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "client", "keys")


# ─── Helpers ────────────────────────────────────────────────


def _auth():
    return (session.get("username"), session.get("password"))


def _require_login():
    if not session.get("username"):
        return jsonify({"error": "Not logged in"}), 401
    return None


def _get_public_key(username: str):
    resp = requests.get(
        f"{SERVER_URL}/users/{username}/public_key", auth=_auth()
    )
    if resp.status_code == 200:
        return load_public_key_from_pem(resp.json()["public_key"])
    return None


# ─── Pages ──────────────────────────────────────────────────


@app.route("/")
def index():
    return render_template("index.html")


# ─── Session ────────────────────────────────────────────────


@app.route("/api/session")
def get_session():
    return jsonify({"username": session.get("username")}), 200


@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    resp = requests.post(
        f"{SERVER_URL}/login", json={"username": username, "password": password}
    )

    if not resp.ok:
        return jsonify(resp.json()), resp.status_code

    # Verify local private key is accessible
    try:
        load_private_key(username, password, KEYS_DIR)
    except Exception:
        return jsonify({"error": "Private key not found or wrong password"}), 401

    session["username"] = username
    session["password"] = password
    return jsonify({"username": username}), 200


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"}), 200


# ─── Files ──────────────────────────────────────────────────


@app.route("/api/files")
def list_files():
    err = _require_login()
    if err:
        return err

    resp = requests.get(f"{SERVER_URL}/files", auth=_auth())
    return jsonify(resp.json()), resp.status_code


@app.route("/api/files/upload", methods=["POST"])
def upload_file():
    err = _require_login()
    if err:
        return err

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    file_data = file.read()
    filename = file.filename

    ciphertext, nonce, tag, dek = encrypt_file(file_data)

    owner_pub = _get_public_key(session["username"])
    if not owner_pub:
        return jsonify({"error": "Could not retrieve own public key"}), 500

    wrapped_keys = {session["username"]: wrap_dek(dek, owner_pub)}

    share_with = request.form.get("share_with", "")
    if share_with:
        for uname in [u.strip() for u in share_with.split(",") if u.strip()]:
            pub = _get_public_key(uname)
            if pub:
                wrapped_keys[uname] = wrap_dek(dek, pub)

    resp = requests.post(
        f"{SERVER_URL}/files/upload",
        auth=_auth(),
        json={
            "filename": filename,
            "encrypted_blob": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "wrapped_keys": wrapped_keys,
        },
    )
    return jsonify(resp.json()), resp.status_code


@app.route("/api/files/<int:file_id>/download")
def download_file(file_id):
    err = _require_login()
    if err:
        return err

    dl_resp = requests.get(
        f"{SERVER_URL}/files/{file_id}/download", auth=_auth()
    )
    if not dl_resp.ok:
        return jsonify(dl_resp.json()), dl_resp.status_code

    dl = dl_resp.json()
    private_key = load_private_key(session["username"], session["password"], KEYS_DIR)
    dek = unwrap_dek(dl["wrapped_dek"], private_key)

    plaintext = decrypt_file(
        base64.b64decode(dl["encrypted_blob"]),
        base64.b64decode(dl["nonce"]),
        base64.b64decode(dl["tag"]),
        dek,
    )

    safe_name = os.path.basename(dl["filename"])
    return Response(
        plaintext,
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "Content-Type": "application/octet-stream",
        },
    )


# ─── ACL ────────────────────────────────────────────────────


@app.route("/api/files/<int:file_id>/acl")
def get_acl(file_id):
    err = _require_login()
    if err:
        return err

    resp = requests.get(f"{SERVER_URL}/files/{file_id}/acl", auth=_auth())
    return jsonify(resp.json()), resp.status_code


@app.route("/api/files/<int:file_id>/grant", methods=["POST"])
def grant_access(file_id):
    err = _require_login()
    if err:
        return err

    target_username = request.json.get("username", "").strip()
    if not target_username:
        return jsonify({"error": "Username required"}), 400

    # Download file to get the DEK, then wrap it for the new user
    dl_resp = requests.get(
        f"{SERVER_URL}/files/{file_id}/download", auth=_auth()
    )
    if not dl_resp.ok:
        return jsonify(dl_resp.json()), dl_resp.status_code

    dl = dl_resp.json()
    private_key = load_private_key(session["username"], session["password"], KEYS_DIR)
    dek = unwrap_dek(dl["wrapped_dek"], private_key)

    target_pub = _get_public_key(target_username)
    if not target_pub:
        return jsonify({"error": f"User '{target_username}' not found"}), 404

    wrapped = wrap_dek(dek, target_pub)

    resp = requests.post(
        f"{SERVER_URL}/files/{file_id}/grant",
        auth=_auth(),
        json={"username": target_username, "wrapped_dek": wrapped},
    )
    return jsonify(resp.json()), resp.status_code


@app.route("/api/files/<int:file_id>/revoke", methods=["POST"])
def revoke_access(file_id):
    err = _require_login()
    if err:
        return err

    target_username = request.json.get("username", "").strip()
    if not target_username:
        return jsonify({"error": "Username required"}), 400

    # Download and decrypt the file
    dl_resp = requests.get(
        f"{SERVER_URL}/files/{file_id}/download", auth=_auth()
    )
    if not dl_resp.ok:
        return jsonify(dl_resp.json()), dl_resp.status_code

    dl = dl_resp.json()
    private_key = load_private_key(session["username"], session["password"], KEYS_DIR)
    dek = unwrap_dek(dl["wrapped_dek"], private_key)
    plaintext = decrypt_file(
        base64.b64decode(dl["encrypted_blob"]),
        base64.b64decode(dl["nonce"]),
        base64.b64decode(dl["tag"]),
        dek,
    )

    # Get current ACL, exclude the revoked user
    acl_resp = requests.get(f"{SERVER_URL}/files/{file_id}/acl", auth=_auth())
    if not acl_resp.ok:
        return jsonify(acl_resp.json()), acl_resp.status_code

    remaining = [
        u["username"]
        for u in acl_resp.json()["acl"]
        if u["username"] != target_username
    ]

    # Re-encrypt with a fresh DEK
    new_ct, new_nonce, new_tag, new_dek = encrypt_file(plaintext)

    wrapped_keys = {}
    for uname in remaining:
        pub = _get_public_key(uname)
        if pub:
            wrapped_keys[uname] = wrap_dek(new_dek, pub)

    resp = requests.put(
        f"{SERVER_URL}/files/{file_id}/update",
        auth=_auth(),
        json={
            "encrypted_blob": base64.b64encode(new_ct).decode(),
            "nonce": base64.b64encode(new_nonce).decode(),
            "tag": base64.b64encode(new_tag).decode(),
            "wrapped_keys": wrapped_keys,
        },
    )
    return jsonify(resp.json()), resp.status_code


# ─── Entry Point ────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
