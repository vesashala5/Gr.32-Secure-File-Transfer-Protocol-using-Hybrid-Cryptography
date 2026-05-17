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

        def handle_download(conn, session_aes_key, fname):
    """
    Handles file download request from client.

    Important:
    - The file in storage is encrypted.
    - Server loads the encrypted AES key from .key file.
    - Server decrypts that AES key using server private RSA key.
    - Server uses the same AES key to decrypt the stored file.
    - Then server re-encrypts plaintext with current session AES key for transfer.
    """

    try:
        file_path = encrypted_file_path(fname)
        key_path = encrypted_key_path(fname)

        if not os.path.exists(file_path):
            send_msg(conn, "FAIL", b"File not found.")
            print(f"[DOWNLOAD] File not found: {file_path}")
            return

        if not os.path.exists(key_path):
            send_msg(conn, "FAIL", b"Encryption key file not found.")
            print(f"[DOWNLOAD] Key file not found: {key_path}")
            return

        # Read encrypted file from storage
        with open(file_path, "rb") as f:
            encrypted_for_storage = f.read()

        # Read encrypted AES key
        with open(key_path, "rb") as f:
            encrypted_file_aes_key = f.read()

        # Decrypt the AES key using server private RSA key
        file_aes_key = rsa_decrypt(srv_priv, encrypted_file_aes_key)

        # Decrypt the stored file using the same AES key used during upload
        plaintext_data = aes_decrypt(file_aes_key, encrypted_for_storage)

        # Create hash and signature for integrity/authentication
        file_hash = sha256(plaintext_data)
        sig = sign(srv_priv, file_hash)

        # Encrypt plaintext again with session AES key before sending to client
        encrypted_for_transfer = aes_encrypt(session_aes_key, plaintext_data)

        send_msg(conn, "START")
        send_msg(conn, "SIGN", sig)
        send_msg(conn, "HASH", file_hash)

        for i in range(0, len(encrypted_for_transfer), CHUNK):
            send_msg(conn, "CHUNK", encrypted_for_transfer[i:i + CHUNK])

        send_msg(conn, "END")

        print(f"[DOWNLOAD] Encrypted file decrypted from storage and sent: {file_path}")

    except Exception as e:
        send_msg(conn, "FAIL", str(e).encode())
        print("[DOWNLOAD ERROR]", e)


def handle_client(conn, addr):
    """
    Handles one client connection.
    """

    print(f"[CONNECTED] Client connected from {addr}")

    try:
          # =========================
        # KEY EXCHANGE
        # =========================

        send_msg(conn, "SERVER_PUB", serialize_pub(srv_pub))

        tag, client_pub_pem = recv_msg(conn)

        if tag != "CLIENT_PUB":
            send_msg(conn, "FAIL", b"Expected client public key.")
            return

        client_pub = load_pub(client_pub_pem)

        tag, enc_session_aes = recv_msg(conn)

        if tag != "AES_KEY":
            send_msg(conn, "FAIL", b"Expected AES session key.")
            return

        session_aes_key = rsa_decrypt(srv_priv, enc_session_aes)

        send_msg(conn, "ACK", b"Key exchange successful.")

        print("[KEY EXCHANGE] Completed successfully.")