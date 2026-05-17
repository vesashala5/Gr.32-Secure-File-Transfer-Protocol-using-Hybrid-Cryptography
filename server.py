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
