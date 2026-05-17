import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_rsa_keys():
    """
    Generates a 2048-bit RSA private/public key pair.
    """
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public = private.public_key()
    return private, public


def serialize_pub(pub):
    """
    Converts public key to PEM bytes.
    """
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_pub(pem):
    """
    Loads public key from PEM bytes.
    """
    return serialization.load_pem_public_key(pem)


def serialize_priv(priv):
    """
    Converts private key to PEM bytes.
    No password is used here for simplicity in this assignment.
    """
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def load_priv(pem):
    """
    Loads private key from PEM bytes.
    """
    return serialization.load_pem_private_key(
        pem,
        password=None
    )

def rsa_encrypt(pub, data):
    """
    Encrypts small data, such as AES key, using RSA OAEP.
    """
    return pub.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(priv, data):
    """
    Decrypts data encrypted with the matching RSA public key.
    """
    return priv.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )



def gen_aes():
    """
    Generates a random 256-bit AES key.
    """
    return os.urandom(32)


def aes_encrypt(key, data):
    """
    Encrypts data using AES-CFB.
    The IV is prepended to the encrypted data.
    """
    iv = os.urandom(16)

    cipher = Cipher(
        algorithms.AES(key),
        modes.CFB(iv)
    )

    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()

    return iv + encrypted


def aes_decrypt(key, data):
    """
    Decrypts AES-CFB encrypted data.
    The first 16 bytes are the IV.
    """
    iv = data[:16]
    encrypted = data[16:]

    cipher = Cipher(
        algorithms.AES(key),
        modes.CFB(iv)
    )

    decryptor = cipher.decryptor()

    return decryptor.update(encrypted) + decryptor.finalize()


def sha256(data):
    """
    Generates SHA-256 hash.
    """
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


def sign(priv, data):
    """
    Signs data using RSA-PSS.
    """
    return priv.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify(pub, sig, data):
    """
    Verifies RSA-PSS signature.
    """
    try:
        pub.verify(
            sig,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False