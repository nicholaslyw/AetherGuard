import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─── Key Pair Generation ────────────────────────────────────


def generate_key_pair(username: str, password: str, keys_dir: str):
    """Generate RSA key pair. Encrypt private key with password."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Encrypt and save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode()
        ),
    )
    private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
    with open(private_key_path, "wb") as f:
        f.write(private_pem)

    # Save public key
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_path = os.path.join(keys_dir, f"{username}_public.pem")
    with open(public_key_path, "wb") as f:
        f.write(public_pem)

    return public_pem.decode()


def load_private_key(username: str, password: str, keys_dir: str):
    """Load and decrypt the private key from disk."""
    path = os.path.join(keys_dir, f"{username}_private.pem")
    with open(path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=password.encode()
        )
    return private_key


def load_public_key_from_pem(pem_string: str):
    """Load a public key from a PEM string."""
    return serialization.load_pem_public_key(pem_string.encode())


# ─── File Encryption (AES-GCM) ──────────────────────────────


def encrypt_file(file_data: bytes):
    """Encrypt file data with a new random DEK.

    Returns (encrypted_data, nonce, tag, dek).
    """
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aesgcm = AESGCM(dek)

    # AES-GCM appends the tag to the ciphertext
    ciphertext_with_tag = aesgcm.encrypt(nonce, file_data, None)

    # Separate ciphertext and tag (last 16 bytes)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    return ciphertext, nonce, tag, dek


def decrypt_file(
    encrypted_data: bytes, nonce: bytes, tag: bytes, dek: bytes
):
    """Decrypt file data using DEK."""
    aesgcm = AESGCM(dek)
    # Reassemble ciphertext + tag
    ciphertext_with_tag = encrypted_data + tag
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)


# ─── Key Wrapping (RSA-OAEP) ────────────────────────────────


def wrap_dek(dek: bytes, public_key) -> str:
    """Encrypt the DEK with a recipient's public key."""
    wrapped = public_key.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(wrapped).decode()


def unwrap_dek(wrapped_dek_b64: str, private_key) -> bytes:
    """Decrypt the DEK with your private key."""
    wrapped = base64.b64decode(wrapped_dek_b64)
    return private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )