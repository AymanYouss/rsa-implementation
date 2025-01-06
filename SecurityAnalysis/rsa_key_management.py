import json
import os
import sys
import time
from datetime import datetime, timedelta

from RSA.rsa import RSA, load_key_from_file, save_key_to_file


class RSAKeyManager:
    """
    Demonstrate a simplified RSA key management approach.
    Stores metadata such as creation time, expiration, etc.
    """
    def __init__(self, key_size=2048, expiration_days=365):
        self.key_size = key_size
        self.expiration_days = expiration_days
        self.public_key_file = "public_key.txt"
        self.private_key_file = "private_key.txt"
        self.meta_file = "key_metadata.json"
        self.rsa=None
    def generate_and_save_keypair(self):
        print("Generating RSA keypair...")
        rsa = RSA(key_size=self.key_size)
        rsa.generate_keypair()
        self.rsa=rsa


        print(f"Keys saved to {self.public_key_file} and {self.private_key_file}")
        print(f"Metadata saved to {self.meta_file}")

    def load_keypair(self):
        print("Loading RSA keypair from files...")
        if not os.path.exists(self.public_key_file) or not os.path.exists(self.private_key_file):
            print("Key files not found. Generate keys first.")
            return None, None
        public_key = load_key_from_file(self.public_key_file)
        private_key = load_key_from_file(self.private_key_file)

        return public_key, private_key

    def is_key_expired(self):
        rsa_app_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'app', 'keys')
        meta_file_path = os.path.join(rsa_app_dir, self.meta_file)

        if not os.path.exists(meta_file_path):
            print("Metadata file not found. Cannot check expiration.")
            return True

        with open(meta_file_path, 'r') as f:
            metadata = json.load(f)
        expiration_time = datetime.fromisoformat(metadata["expiration_time"])
        
        if datetime.utcnow() > expiration_time:
            print("Key has expired.")
            return True
        print("Key is still valid.")
        return False

    def rotate_keys(self):
        """
        If the key is expired, generate a new keypair. Otherwise do nothing.
        """
        if self.is_key_expired():
            print("Rotating RSA keys due to expiration...")
            self.generate_and_save_keypair()
        else:
            print("Keys are not expired. No rotation needed.")

def demo_key_management():
    manager = RSAKeyManager(key_size=512, expiration_days=1)  # smaller key for quick demonstration
    manager.generate_and_save_keypair()

    # Simulate a usage scenario
    public_key, private_key = manager.load_keypair()
    if public_key and private_key:
        print(f"Loaded public key: {public_key}")
        print(f"Loaded private key: {private_key}")

    print("\nChecking if key is expired right after generation:")
    manager.is_key_expired()

    # Optionally, simulate waiting for expiration or forcibly rotating
    print("\nRotating keys (will only generate new ones if expired):")
    manager.rotate_keys()

if __name__ == "__main__":
    demo_key_management()
