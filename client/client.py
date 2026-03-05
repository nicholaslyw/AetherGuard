import requests
import base64
import os
import sys
from crypto_utils import (
    generate_key_pair,
    load_private_key,
    load_public_key_from_pem,
    encrypt_file,
    decrypt_file,
    wrap_dek,
    unwrap_dek,
)

SERVER_URL = "http://server:5000"
KEYS_DIR = "/app/keys"
DOWNLOADS_DIR = "/app/downloads"

# Session state
current_user = None
current_password = None


# ─── API Helpers ─────────────────────────────────────────────


def auth():
    """Return basic auth tuple."""
    return (current_user, current_password)


def get_public_key_for_user(username: str):
    """Fetch a user's public key from the server."""
    resp = requests.get(
        f"{SERVER_URL}/users/{username}/public_key", auth=auth()
    )
    if resp.status_code == 200:
        pem = resp.json()["public_key"]
        return load_public_key_from_pem(pem)
    print(f"  Error fetching key for '{username}': {resp.json()}")
    return None


# ─── Commands ────────────────────────────────────────────────


def do_register():
    username = input("  Username: ").strip()
    password = input("  Password: ").strip()

    print("  Generating RSA-4096 key pair...")
    public_key_pem = generate_key_pair(username, password, KEYS_DIR)

    resp = requests.post(f"{SERVER_URL}/register", json={
        "username": username,
        "password": password,
        "public_key": public_key_pem,
    })
    print(f"  Server: {resp.json()['message'] if resp.ok else resp.json()}")


def do_login():
    global current_user, current_password
    username = input("  Username: ").strip()
    password = input("  Password: ").strip()

    resp = requests.post(f"{SERVER_URL}/login", json={
        "username": username,
        "password": password,
    })

    if resp.ok:
        # Verify we can load the private key
        try:
            load_private_key(username, password, KEYS_DIR)
        except Exception:
            print("  Error: Private key not found or wrong password.")
            return
        current_user = username
        current_password = password
        print(f"  Logged in as '{username}'.")
    else:
        print(f"  Error: {resp.json()}")


def do_upload():
    filepath = input("  File path to upload: ").strip()
    if not os.path.exists(filepath):
        print("  File not found.")
        return

    filename = os.path.basename(filepath)
    with open(filepath, "rb") as f:
        file_data = f.read()

    print("  Encrypting file locally...")
    ciphertext, nonce, tag, dek = encrypt_file(file_data)

    # Wrap the DEK for the owner
    owner_pub = get_public_key_for_user(current_user)
    if not owner_pub:
        return

    wrapped_keys = {current_user: wrap_dek(dek, owner_pub)}

    # Optionally share with others at upload time
    share_with = input(
        "  Share with (comma-separated usernames, or blank): "
    ).strip()
    if share_with:
        for uname in [u.strip() for u in share_with.split(",")]:
            pub = get_public_key_for_user(uname)
            if pub:
                wrapped_keys[uname] = wrap_dek(dek, pub)

    resp = requests.post(
        f"{SERVER_URL}/files/upload",
        auth=auth(),
        json={
            "filename": filename,
            "encrypted_blob": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "wrapped_keys": wrapped_keys,
        },
    )
    print(f"  Server: {resp.json()}")


def do_list():
    resp = requests.get(f"{SERVER_URL}/files", auth=auth())
    if resp.ok:
        files = resp.json()["files"]
        if not files:
            print("  No files available.")
            return
        print(f"  {'ID':<6} {'Filename':<30} {'Owner':<15}")
        print("  " + "-" * 51)
        for f in files:
            print(
                f"  {f['file_id']:<6} {f['filename']:<30} {f['owner']:<15}"
            )
    else:
        print(f"  Error: {resp.json()}")


def do_download():
    file_id = input("  File ID to download: ").strip()

    resp = requests.get(
        f"{SERVER_URL}/files/{file_id}/download", auth=auth()
    )
    if not resp.ok:
        print(f"  Error: {resp.json()}")
        return

    data = resp.json()
    print("  Decrypting file locally...")

    private_key = load_private_key(current_user, current_password, KEYS_DIR)
    dek = unwrap_dek(data["wrapped_dek"], private_key)

    plaintext = decrypt_file(
        base64.b64decode(data["encrypted_blob"]),
        base64.b64decode(data["nonce"]),
        base64.b64decode(data["tag"]),
        dek,
    )

    out_path = os.path.join(DOWNLOADS_DIR, data["filename"])
    with open(out_path, "wb") as f:
        f.write(plaintext)

    print(f"  File saved to {out_path}")


def do_grant():
    file_id = input("  File ID: ").strip()
    target = input("  Username to grant access: ").strip()

    # Owner must decrypt their own DEK first
    resp = requests.get(
        f"{SERVER_URL}/files/{file_id}/download", auth=auth()
    )
    if not resp.ok:
        print(f"  Error: {resp.json()}")
        return

    data = resp.json()
    private_key = load_private_key(current_user, current_password, KEYS_DIR)
    dek = unwrap_dek(data["wrapped_dek"], private_key)

    # Wrap DEK for target user
    target_pub = get_public_key_for_user(target)
    if not target_pub:
        return

    wrapped = wrap_dek(dek, target_pub)

    resp = requests.post(
        f"{SERVER_URL}/files/{file_id}/grant",
        auth=auth(),
        json={"username": target, "wrapped_dek": wrapped},
    )
    print(f"  Server: {resp.json()}")


def do_revoke():
    file_id = input("  File ID: ").strip()
    target = input("  Username to revoke access: ").strip()

    resp = requests.post(
        f"{SERVER_URL}/files/{file_id}/revoke",
        auth=auth(),
        json={"username": target},
    )
    print(f"  Server: {resp.json()}")


# ─── Main Menu ──────────────────────────────────────────────


def main():
    print("=" * 50)
    print("   Secure File Sharing Platform")
    print("=" * 50)

    while True:
        print()
        if current_user:
            print(f"  Logged in as: {current_user}")
            print("  1. Upload file")
            print("  2. List files")
            print("  3. Download file")
            print("  4. Grant access")
            print("  5. Revoke access")
            print("  6. Logout")
            print("  7. Exit")
        else:
            print("  1. Register")
            print("  2. Login")
            print("  3. Exit")

        choice = input("\n  Choice: ").strip()

        if current_user:
            if choice == "1":
                do_upload()
            elif choice == "2":
                do_list()
            elif choice == "3":
                do_download()
            elif choice == "4":
                do_grant()
            elif choice == "5":
                do_revoke()
            elif choice == "6":
                globals()["current_user"] = None
                globals()["current_password"] = None
                print("  Logged out.")
            elif choice == "7":
                print("  Goodbye.")
                sys.exit(0)
        else:
            if choice == "1":
                do_register()
            elif choice == "2":
                do_login()
            elif choice == "3":
                print("  Goodbye.")
                sys.exit(0)


if __name__ == "__main__":
    main()