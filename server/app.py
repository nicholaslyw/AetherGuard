from flask import Flask, request, jsonify, send_file
from models import get_db, init_db
from crypto_utils import hash_password, verify_password
import os
import base64
import uuid

app = Flask(__name__)
STORAGE_PATH = "/app/storage"


# ─── Auth Helpers ───────────────────────────────────────────


def authenticate(req):
    """Extract and verify basic auth credentials."""
    auth = req.authorization
    if not auth:
        return None
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (auth.username,)
    ).fetchone()
    conn.close()
    if user and verify_password(auth.password, user["password_hash"]):
        return user
    return None


# ─── Registration ───────────────────────────────────────────


@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    public_key = data.get("public_key")

    if not all([username, password, public_key]):
        return jsonify({"error": "Missing fields"}), 400

    pw_hash = hash_password(password)

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, public_key)"
            " VALUES (?, ?, ?)",
            (username, pw_hash, public_key),
        )
        conn.commit()
    except Exception:
        conn.close()
        return jsonify({"error": "Username already exists"}), 409
    conn.close()
    return jsonify({"message": f"User '{username}' registered"}), 201


# ─── Login ──────────────────────────────────────────────────


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if user and verify_password(password, user["password_hash"]):
        return jsonify({
            "message": "Login successful",
            "user_id": user["id"],
        }), 200
    return jsonify({"error": "Invalid credentials"}), 401


# ─── Get Public Key ─────────────────────────────────────────


@app.route("/users/<username>/public_key", methods=["GET"])
def get_public_key(username):
    user = authenticate(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    target = conn.execute(
        "SELECT public_key FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if not target:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"public_key": target["public_key"]}), 200


# ─── Upload File ────────────────────────────────────────────


@app.route("/files/upload", methods=["POST"])
def upload_file():
    user = authenticate(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    filename = data.get("filename")
    encrypted_blob_b64 = data.get("encrypted_blob")
    nonce_b64 = data.get("nonce")
    tag_b64 = data.get("tag")
    wrapped_keys = data.get("wrapped_keys")  # dict: {username: wrapped_dek}

    if not all([filename, encrypted_blob_b64, nonce_b64, tag_b64,
                wrapped_keys]):
        return jsonify({"error": "Missing fields"}), 400

    # Save encrypted blob to disk
    file_uuid = str(uuid.uuid4())
    blob_path = os.path.join(STORAGE_PATH, file_uuid)
    with open(blob_path, "wb") as f:
        f.write(base64.b64decode(encrypted_blob_b64))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO files (filename, owner_id, blob_path, nonce, tag)"
        " VALUES (?, ?, ?, ?, ?)",
        (filename, user["id"], blob_path, nonce_b64, tag_b64),
    )
    file_id = cursor.lastrowid

    # Store wrapped DEKs for each user in the ACL
    for target_username, wrapped_dek in wrapped_keys.items():
        target_user = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (target_username,),
        ).fetchone()
        if target_user:
            cursor.execute(
                "INSERT INTO access_control"
                " (file_id, user_id, wrapped_dek)"
                " VALUES (?, ?, ?)",
                (file_id, target_user["id"], wrapped_dek),
            )

    conn.commit()
    conn.close()
    return jsonify({
        "message": "File uploaded",
        "file_id": file_id,
    }), 201


# ─── List Files ─────────────────────────────────────────────


@app.route("/files", methods=["GET"])
def list_files():
    user = authenticate(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    files = conn.execute(
        """
        SELECT f.id, f.filename, u.username AS owner
        FROM files f
        JOIN access_control ac ON f.id = ac.file_id
        JOIN users u ON f.owner_id = u.id
        WHERE ac.user_id = ?
        """,
        (user["id"],),
    ).fetchall()
    conn.close()

    return jsonify({
        "files": [
            {
                "file_id": f["id"],
                "filename": f["filename"],
                "owner": f["owner"],
            }
            for f in files
        ]
    }), 200


# ─── Download File ──────────────────────────────────────────


@app.route("/files/<int:file_id>/download", methods=["GET"])
def download_file(file_id):
    user = authenticate(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()

    access = conn.execute(
        "SELECT wrapped_dek FROM access_control"
        " WHERE file_id = ? AND user_id = ?",
        (file_id, user["id"]),
    ).fetchone()

    if not access:
        conn.close()
        return jsonify({"error": "Access denied"}), 403

    file_info = conn.execute(
        "SELECT * FROM files WHERE id = ?", (file_id,)
    ).fetchone()
    conn.close()

    if not file_info:
        return jsonify({"error": "File not found"}), 404

    with open(file_info["blob_path"], "rb") as f:
        encrypted_blob = base64.b64encode(f.read()).decode()

    return jsonify({
        "filename": file_info["filename"],
        "encrypted_blob": encrypted_blob,
        "nonce": file_info["nonce"],
        "tag": file_info["tag"],
        "wrapped_dek": access["wrapped_dek"],
    }), 200


# ─── List ACL (Any Authorized User) ────────────────────────


@app.route("/files/<int:file_id>/acl", methods=["GET"])
def get_acl(file_id):
    user = authenticate(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()

    # Allow any user who is in the ACL for this file, not just the owner.
    # This is required so that non-owner users can retrieve the full user list
    # when re-wrapping the DEK after a file modification.
    access = conn.execute(
        "SELECT 1 FROM access_control WHERE file_id = ? AND user_id = ?",
        (file_id, user["id"]),
    ).fetchone()

    if not access:
        conn.close()
        return jsonify({"error": "Access denied or file not found"}), 403

    file_info = conn.execute(
        "SELECT * FROM files WHERE id = ?", (file_id,)
    ).fetchone()

    if not file_info:
        conn.close()
        return jsonify({"error": "File not found"}), 404

    acl = conn.execute(
        """
        SELECT u.username, u.id AS user_id
        FROM access_control ac
        JOIN users u ON ac.user_id = u.id
        WHERE ac.file_id = ?
        ORDER BY u.username
        """,
        (file_id,),
    ).fetchall()
    conn.close()

    return jsonify({
        "file_id": file_id,
        "filename": file_info["filename"],
        "acl": [
            {"username": a["username"], "user_id": a["user_id"]}
            for a in acl
        ],
    }), 200


# ─── Grant Access (Owner Only) ──────────────────────────────


@app.route("/files/<int:file_id>/grant", methods=["POST"])
def grant_access(file_id):
    user = authenticate(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()

    file_info = conn.execute(
        "SELECT * FROM files WHERE id = ? AND owner_id = ?",
        (file_id, user["id"]),
    ).fetchone()

    if not file_info:
        conn.close()
        return jsonify({"error": "Not owner or file not found"}), 403

    data = request.json
    target_username = data.get("username")
    wrapped_dek = data.get("wrapped_dek")

    target_user = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (target_username,),
    ).fetchone()

    if not target_user:
        conn.close()
        return jsonify({"error": "Target user not found"}), 404

    try:
        conn.execute(
            "INSERT INTO access_control"
            " (file_id, user_id, wrapped_dek)"
            " VALUES (?, ?, ?)",
            (file_id, target_user["id"], wrapped_dek),
        )
        conn.commit()
    except Exception:
        conn.close()
        return jsonify({"error": "Access already granted"}), 409

    conn.close()
    return jsonify({
        "message": f"Access granted to '{target_username}'",
    }), 200


# ─── Revoke Access (Owner Only) ─────────────────────────────


@app.route("/files/<int:file_id>/revoke", methods=["POST"])
def revoke_access(file_id):
    user = authenticate(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()

    file_info = conn.execute(
        "SELECT * FROM files WHERE id = ? AND owner_id = ?",
        (file_id, user["id"]),
    ).fetchone()

    if not file_info:
        conn.close()
        return jsonify({"error": "Not owner or file not found"}), 403

    data = request.json
    target_username = data.get("username")

    target_user = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (target_username,),
    ).fetchone()

    if not target_user:
        conn.close()
        return jsonify({"error": "Target user not found"}), 404

    conn.execute(
        "DELETE FROM access_control"
        " WHERE file_id = ? AND user_id = ?",
        (file_id, target_user["id"]),
    )
    conn.commit()
    conn.close()

    return jsonify({
        "message": f"Access revoked for '{target_username}'",
    }), 200


# ─── Re-upload (Modify) File ────────────────────────────────


@app.route("/files/<int:file_id>/update", methods=["PUT"])
def update_file(file_id):
    user = authenticate(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()

    access = conn.execute(
        "SELECT * FROM access_control"
        " WHERE file_id = ? AND user_id = ?",
        (file_id, user["id"]),
    ).fetchone()

    if not access:
        conn.close()
        return jsonify({"error": "Access denied"}), 403

    file_info = conn.execute(
        "SELECT * FROM files WHERE id = ?", (file_id,)
    ).fetchone()

    if not file_info:
        conn.close()
        return jsonify({"error": "File not found"}), 404

    data = request.json
    encrypted_blob_b64 = data.get("encrypted_blob")
    nonce_b64 = data.get("nonce")
    tag_b64 = data.get("tag")
    wrapped_keys = data.get("wrapped_keys")

    if not all([encrypted_blob_b64, nonce_b64, tag_b64, wrapped_keys]):
        conn.close()
        return jsonify({"error": "Missing fields"}), 400

    # Overwrite the blob on disk
    with open(file_info["blob_path"], "wb") as f:
        f.write(base64.b64decode(encrypted_blob_b64))

    cursor = conn.cursor()
    cursor.execute(
        "UPDATE files SET nonce = ?, tag = ? WHERE id = ?",
        (nonce_b64, tag_b64, file_id),
    )

    # Replace all wrapped DEKs since the file has been re-encrypted with a new key
    cursor.execute(
        "DELETE FROM access_control WHERE file_id = ?", (file_id,)
    )
    for target_username, w_dek in wrapped_keys.items():
        target_user = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (target_username,),
        ).fetchone()
        if target_user:
            cursor.execute(
                "INSERT INTO access_control"
                " (file_id, user_id, wrapped_dek)"
                " VALUES (?, ?, ?)",
                (file_id, target_user["id"], w_dek),
            )

    conn.commit()
    conn.close()
    return jsonify({"message": "File updated"}), 200


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)