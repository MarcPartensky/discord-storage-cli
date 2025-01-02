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

# import os
# import hashlib
# import ecies
# import argparse
# from ecdsa import SECP256k1, SigningKey
# from ecdsa.util import string_to_number

# # 1. Générer la clé privée à partir du mot de passe avec PBKDF2
# # password = b"monMotDePasseSecret!"
# SALT = os.environ["SALT"].encode()
# DISCORD_BOT_API_URL = os.environ["DISCORD_BOT_API_URL"]
# # ITERATIONS = os.environ["ITERATIONS"]
# ITERATIONS = 100000

# # Générer une clé privée sécurisée avec PBKDF2
# private_key_bytes = hashlib.pbkdf2_hmac('sha256', input("password").encode(), SALT, ITERATIONS, dklen=32)

# # Vérifier que la clé privée est valide pour secp256k1
# order = SECP256k1.order
# private_key_int = string_to_number(private_key_bytes) % order

# # 2. Créer la clé privée et la clé publique
# sk = SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
# public_key = sk.get_verifying_key().to_string("compressed")

# # 3. Signer un message (par exemple, le texte à chiffrer)
# message = b"Hello, ECIES avec signature !"
# message_hash = hashlib.sha256(message).digest()
# signature = sk.sign(message_hash)

# # 4. Chiffrer le message signé avec la clé publique du destinataire (exemple avec une clé publique générique)
# recipient_public_key = public_key  # Utiliser la clé publique du destinataire ici
# encrypted_message = ecies.encrypt(recipient_public_key, message + signature)

# # 5. Déchiffrer le message
# decrypted_message = ecies.decrypt(private_key_bytes, encrypted_message)

# # Le message décrypté doit contenir le texte original + la signature
# original_message = decrypted_message[:-len(signature)]  # Extraire le message original
# received_signature = decrypted_message[-len(signature):]  # Extraire la signature

# # Vérifier la signature avec la clé publique
# verifying_key = sk.get_verifying_key()
# assert verifying_key.verify(received_signature, hashlib.sha256(original_message).digest())

# print("Message original :", original_message.decode())

import hashlib

# import os
import getpass
import ecies
import fire
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import string_to_number


class ECCManager:
    def __init__(self, salt=b"default_salt", iterations=100000):
        self.salt = salt
        self.iterations = iterations

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
        with open("private_key.pem", "wb") as priv_file:
            priv_file.write(private_key)

        with open("public_key.pem", "wb") as pub_file:
            pub_file.write(public_key)

        print("Keys generated and saved as private_key.pem and public_key.pem")

    def encrypt(self, public_key_path: str, input_file: str, output_file: str):
        """
        Encrypt a file using a public key.
        """
        with open(public_key_path, "rb") as pub_file:
            public_key = pub_file.read()

        with open(input_file, "rb") as infile:
            plaintext = infile.read()

        encrypted = ecies.encrypt(public_key, plaintext)

        with open(output_file, "wb") as outfile:
            outfile.write(encrypted)

        print(f"File encrypted and saved to {output_file}")

    def decrypt(self, private_key_path: str, input_file: str, output_file: str):
        """
        Decrypt a file using a private key.
        """
        with open(private_key_path, "rb") as priv_file:
            private_key = priv_file.read()

        with open(input_file, "rb") as infile:
            encrypted = infile.read()

        decrypted = ecies.decrypt(private_key, encrypted)

        with open(output_file, "wb") as outfile:
            outfile.write(decrypted)

        print(f"File decrypted and saved to {output_file}")

    def sign(self, private_key_path: str, input_file: str, signature_file: str):
        """
        Sign a file using a private key.
        """
        with open(private_key_path, "rb") as priv_file:
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
    fire.Fire(ECCManager)
