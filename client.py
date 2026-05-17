import socket
import os
import sys

from crypto_utils import *
from protocol import *


HOST = "127.0.0.1"
PORT = 5001


def connect_and_exchange_keys():
    """
    Connects to server and performs hybrid cryptography key exchange.

    Steps:
    1. Client generates RSA key pair.
    2. Client receives server public key.
    3. Client sends its own public key.
    4. Client generates AES key.
    5. Client encrypts AES key using server public key.
    6. Client sends encrypted AES key to server.
    """

    cli_priv, cli_pub = generate_rsa_keys()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # Receive server public key
    tag, srv_pub_pem = recv_msg(s)

    if tag != "SERVER_PUB":
        raise Exception("Server public key was not received.")

    srv_pub = load_pub(srv_pub_pem)

    # Send client public key
    send_msg(s, "CLIENT_PUB", serialize_pub(cli_pub))

    # Generate AES key and send it encrypted with server public key
    aes_key = gen_aes()
    enc_aes = rsa_encrypt(srv_pub, aes_key)
    send_msg(s, "AES_KEY", enc_aes)

    # Wait for confirmation
    tag, msg = recv_msg(s)

    if tag != "ACK":
        raise Exception("Key exchange failed: " + msg.decode(errors="ignore"))

    print("Successful connection to Secure File Transfer Server.")
    print("RSA key pair generated.")
    print("Server public key received.")
    print("AES key encrypted and sent successfully.")

    return s, cli_priv, srv_pub, aes_key