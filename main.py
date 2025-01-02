#!/bin/env python
"""
Requirements:
    - Public key
    - Private key
    - Salt
    - Discord bot API url
Functions:
    - Encrypt and send file to discord
    - Receive file from discord then decrypt
"""

import os
import hashlib
import getpass
import ecies
import fire
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import string_to_number
from dotenv import load_dotenv


class ECCManager:
    def __init__(self):
        self.salt = str(os.environ.get("SALT")).encode("utf-8")
        self.iterations = int(os.environ["ITERATIONS"])
        self.private_key_path = os.environ["PRIVATE_KEY_PATH"]
        self.public_key_path = os.environ["PUBLIC_KEY_PATH"]

    def generate_salt(self):
        """
        Generate a random salt and print it.
        """
        salt = os.urandom(16)
        print(f"Salt: {salt.hex()}")
        # return salt

    def derive_keys(self, password: str):
        """
        Derives a private key and public key from a password.
        """
        # Generate private key bytes using PBKDF2
        private_key_bytes = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), self.salt, self.iterations, dklen=32
        )
        # Ensure the private key is within the valid range for secp256k1
        order = SECP256k1.order
        private_key_int = string_to_number(private_key_bytes) % order

        # Create the SigningKey and public key
        sk = SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
        compressed_public_key = sk.get_verifying_key().to_string("compressed")

        return private_key_bytes, compressed_public_key

    def keygen(self):
        """
        Generate a private and public key from a password and save them to files.
        """
        password = getpass.getpass("password:")
        private_key, public_key = self.derive_keys(password)

        # Save keys to files
        with open(self.private_key_path, "wb") as priv_file:
            priv_file.write(private_key)

        with open(self.public_key_path, "wb") as pub_file:
            pub_file.write(public_key)

        print("Keys generated and saved as private_key.pem and public_key.pem")

    def encrypt(self, input_file: str, output_file: str):
        """
        Encrypt a file using a public key.
        """
        with open(self.public_key_path, "rb") as pub_file:
            public_key = pub_file.read()

        with open(input_file, "rb") as infile:
            plaintext = infile.read()

        encrypted = ecies.encrypt(public_key, plaintext)

        with open(output_file, "wb") as outfile:
            outfile.write(encrypted)

        print(f"File encrypted and saved to {output_file}")

    def decrypt(self, input_file: str, output_file: str):
        """
        Decrypt a file using a private key.
        """
        with open(self.private_key_path, "rb") as priv_file:
            private_key = priv_file.read()

        with open(input_file, "rb") as infile:
            encrypted = infile.read()

        decrypted = ecies.decrypt(private_key, encrypted)

        with open(output_file, "wb") as outfile:
            outfile.write(decrypted)

        print(f"File decrypted and saved to {output_file}")

    def sign(self, input_file: str, signature_file: str):
        """
        Sign a file using a private key.
        """
        with open(self.private_key_path, "rb") as priv_file:
            private_key = priv_file.read()

        sk = SigningKey.from_string(private_key, curve=SECP256k1)

        with open(input_file, "rb") as infile:
            data = infile.read()

        message_hash = hashlib.sha256(data).digest()
        signature = sk.sign(message_hash)

        with open(signature_file, "wb") as sig_file:
            sig_file.write(signature)

        print(f"File signed. Signature saved to {signature_file}")


if __name__ == "__main__":
    load_dotenv()
    fire.Fire(ECCManager)
