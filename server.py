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
