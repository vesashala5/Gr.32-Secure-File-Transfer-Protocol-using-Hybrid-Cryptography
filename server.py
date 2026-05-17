import socket
import os

from crypto_utils import *
from protocol import *


HOST = "127.0.0.1"
PORT = 5001

STORAGE_DIR = "storage"
SERVER_PRIVATE_KEY_FILE = "server_private.pem"
SERVER_PUBLIC_KEY_FILE = "server_public.pem"

os.makedirs(STORAGE_DIR, exist_ok=True)


def load_or_create_server_keys():
    """
    Loads server RSA keys if they already exist.
    If they do not exist, generates new keys and saves them.

    This is important because encrypted files in storage use AES keys
    that are protected with the server public key.
    The same server private key is needed later to decrypt those AES keys.
    """

    if os.path.exists(SERVER_PRIVATE_KEY_FILE) and os.path.exists(SERVER_PUBLIC_KEY_FILE):
        with open(SERVER_PRIVATE_KEY_FILE, "rb") as f:
            private_key = load_priv(f.read())

        with open(SERVER_PUBLIC_KEY_FILE, "rb") as f:
            public_key = load_pub(f.read())

        print("[KEYS] Existing server RSA keys loaded.")
        return private_key, public_key

    private_key, public_key = generate_rsa_keys()

    with open(SERVER_PRIVATE_KEY_FILE, "wb") as f:
        f.write(serialize_priv(private_key))

    with open(SERVER_PUBLIC_KEY_FILE, "wb") as f:
        f.write(serialize_pub(public_key))

    print("[KEYS] New server RSA keys generated and saved.")
    return private_key, public_key


# Server RSA keys
srv_priv, srv_pub = load_or_create_server_keys()


def encrypted_file_path(fname):
    """
    Path where the encrypted uploaded file is stored.
    """
    return os.path.join(STORAGE_DIR, fname)


def encrypted_key_path(fname):
    """
    Path where the AES key for that file is stored.
    The AES key itself is encrypted using the server public key.
    """
    return os.path.join(STORAGE_DIR, fname + ".key")


def handle_upload(conn, client_pub, session_aes_key, fname):
    """
    Handles encrypted file upload from client.

    Important:
    - The file arrives encrypted with the session AES key.
    - Server decrypts it only to verify integrity/signature.
    - Then server encrypts it again with a new file AES key for storage.
    - The same file AES key is saved encrypted with server RSA public key.
    """

    try:
        _, sig = recv_msg(conn)
        _, file_hash = recv_msg(conn)

        encrypted_from_client = b''

        while True:
            tag, chunk = recv_msg(conn)

            if tag == "END":
                break

            if tag != "CHUNK":
                send_msg(conn, "FAIL", b"Invalid chunk received.")
                return

            encrypted_from_client += chunk

        # Decrypt file received from client using session AES key
        plaintext_data = aes_decrypt(session_aes_key, encrypted_from_client)

        # Verify integrity and authenticity
        valid_signature = verify(client_pub, sig, file_hash)
        valid_hash = sha256(plaintext_data) == file_hash

        if not valid_signature or not valid_hash:
            send_msg(conn, "FAIL", b"File verification failed.")
            print("[UPLOAD] Verification failed.")
            return

        # Generate a new AES key specifically for storage
        file_aes_key = gen_aes()

        # Encrypt file for storage
        encrypted_for_storage = aes_encrypt(file_aes_key, plaintext_data)

        # Protect the file AES key with server public RSA key
        encrypted_file_aes_key = rsa_encrypt(srv_pub, file_aes_key)

        # Save encrypted file
        file_path = encrypted_file_path(fname)
        with open(file_path, "wb") as f:
            f.write(encrypted_for_storage)

        # Save encrypted AES key
        key_path = encrypted_key_path(fname)
        with open(key_path, "wb") as f:
            f.write(encrypted_file_aes_key)

        send_msg(conn, "SUCCESS", b"Encrypted file uploaded and stored successfully.")

        print(f"[UPLOAD] Encrypted file stored: {file_path}")
        print(f"[UPLOAD] Encrypted AES key stored: {key_path}")

    except Exception as e:
        send_msg(conn, "FAIL", str(e).encode())
        print("[UPLOAD ERROR]", e)