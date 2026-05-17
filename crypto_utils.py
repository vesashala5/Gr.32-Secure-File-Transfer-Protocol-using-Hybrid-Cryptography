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