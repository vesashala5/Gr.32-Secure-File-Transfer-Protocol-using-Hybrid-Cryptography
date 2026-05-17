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

def upload_file(s, cli_priv, aes_key):
    """
    Uploads a file securely to the server.
    """

    path = input("Enter file path for upload: ").strip()

    if not os.path.exists(path):
        print("File does not exist.")
        return

    name = os.path.basename(path)

    with open(path, "rb") as f:
        data = f.read()

    # Encrypt file with AES
    encrypted = aes_encrypt(aes_key, data)

    # Generate hash and sign it with client's private key
    file_hash = sha256(data)
    sig = sign(cli_priv, file_hash)

    # Send upload request
    send_msg(s, "UPLOAD", name.encode())
    send_msg(s, "SIGN", sig)
    send_msg(s, "HASH", file_hash)

    # Send encrypted file chunks
    for i in range(0, len(encrypted), CHUNK):
        send_msg(s, "CHUNK", encrypted[i:i + CHUNK])

    send_msg(s, "END")

    # Receive result
    tag, msg = recv_msg(s)

    if tag == "SUCCESS":
        print(f"File '{name}' encrypted and sent successfully.")
    else:
        print("Upload failed:", msg.decode(errors="ignore"))

def download_file(s, srv_pub, aes_key):
    """
    Downloads a file securely from the server.
    """

    name = input("Enter filename to download: ").strip()

    send_msg(s, "DOWNLOAD", name.encode())

    tag, msg = recv_msg(s)

    if tag == "FAIL":
        print("Download failed:", msg.decode(errors="ignore"))
        return

    if tag != "START":
        print("Invalid server response.")
        return

    # Receive server signature and hash
    _, sig = recv_msg(s)
    _, file_hash = recv_msg(s)

    encrypted = b''

    while True:
        tag, chunk = recv_msg(s)

        if tag == "END":
            break

        if tag == "FAIL":
            print("Download failed:", chunk.decode(errors="ignore"))
            return

        if tag != "CHUNK":
            print("Invalid chunk received.")
            return

        encrypted += chunk

    # Decrypt file
    data = aes_decrypt(aes_key, encrypted)

    # Verify server signature and file integrity
    valid_signature = verify(srv_pub, sig, file_hash)
    valid_hash = sha256(data) == file_hash

    if not valid_signature:
        print("Download failed: server signature verification failed.")
        return

    if not valid_hash:
        print("Download failed: file integrity check failed.")
        return

    out_file = "downloaded_" + name

    with open(out_file, "wb") as f:
        f.write(data)

    print(f"File downloaded and verified successfully.")
    print(f"Downloaded as: {out_file}")


def main():
    try:
        s, cli_priv, srv_pub, aes_key = connect_and_exchange_keys()

        print()
        print("1. Upload file")
        print("2. Download file")

        choice = input("Choose option: ").strip()

        if choice == "1":
            upload_file(s, cli_priv, aes_key)

        elif choice == "2":
            download_file(s, srv_pub, aes_key)

        else:
            print("Invalid option.")

        s.close()

    except ConnectionRefusedError:
        print("Could not connect to server. Make sure server.py is running first.")

    except Exception as e:
        print("Error:", e)

    finally:
        try:
            s.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()