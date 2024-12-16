import math
import random
import time
from typing import Tuple, Union
import secrets
from datetime import datetime
import os

class RSA:
    def __init__(self, key_size: int = 2048):
        """
        Initialize RSA with specified key size
        
        Args:
            key_size (int): Size of the RSA key in bits (default: 2048)
        """
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        
    def is_prime(self, n: int, k: int = 128) -> bool:
        """Miller-Rabin primality test"""
        if n == 2 or n == 3:
            return True
        if n < 2 or n % 2 == 0:
            return False
        
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
            
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    def generate_prime(self, bits: int) -> int:
        """Generate a prime number of specified bit length"""
        while True:
            n = secrets.randbits(bits)
            n |= (1 << bits - 1) | 1
            if self.is_prime(n, 128):
                return n
    
    def generate_keypair(self) -> None:
        """Generate public and private key pairs"""
        p = self.generate_prime(self.key_size // 2)
        q = self.generate_prime(self.key_size // 2)
        while p == q:
            q = self.generate_prime(self.key_size // 2)
            
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        
        self.public_key = (n, e)
        self.private_key = (n, d)
    
    def pad_message(self, message: Union[str, bytes]) -> int:
        """
        PKCS#1 v1.5 style padding
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Calculate padding length
        max_message_length = self.key_size // 8 - 11  # 11 bytes for padding overhead
        if len(message) > max_message_length:
            raise ValueError(f"Message too long. Maximum length is {max_message_length} bytes")
        
        # Generate padding bytes (excluding 0x00)
        padding_length = self.key_size // 8 - len(message) - 3
        padding = b''
        while len(padding) < padding_length:
            byte = secrets.token_bytes(1)
            if byte != b'\x00':
                padding += byte
        
        # Format: 00 || 02 || PS || 00 || M
        padded = b'\x00\x02' + padding + b'\x00' + message
        return int.from_bytes(padded, 'big')
    
    def unpad_message(self, padded: int) -> bytes:
        """
        Remove PKCS#1 v1.5 style padding
        """
        padded_bytes = padded.to_bytes((self.key_size + 7) // 8, 'big')
        
        # Check initial bytes
        if padded_bytes[0] != 0 or padded_bytes[1] != 2:
            raise ValueError("Invalid padding format")
        
        # Find separator
        separator_index = 2
        while separator_index < len(padded_bytes):
            if padded_bytes[separator_index] == 0:
                break
            separator_index += 1
            
        if separator_index < 10 or separator_index == len(padded_bytes):
            raise ValueError("Invalid padding length")
        
        return padded_bytes[separator_index + 1:]
    
    def encrypt(self, message: Union[str, bytes]) -> int:
        """
        Encrypt a message using public key
        """
        if not self.public_key:
            raise ValueError("No public key available")
            
        n, e = self.public_key
        padded = self.pad_message(message)
        
        # Add timing variation protection
        start_time = time.time()
        cipher = pow(padded, e, n)
        time.sleep(0.001 - ((time.time() - start_time) % 0.001))
        
        return cipher
    
    def decrypt(self, cipher: int) -> bytes:
        """
        Decrypt a message using private key
        """
        if not self.private_key:
            raise ValueError("No private key available")
            
        n, d = self.private_key
        if cipher >= n:
            raise ValueError("Ciphertext too large")
            
        # Add timing variation protection
        start_time = time.time()
        padded = pow(cipher, d, n)
        time.sleep(0.001 - ((time.time() - start_time) % 0.001))
        
        return self.unpad_message(padded)

def save_key_to_file(key: Tuple[int, int], filename: str) -> None:
    """Save a key to a file"""
    with open(filename, 'w') as f:
        f.write(f"{key[0]}\n{key[1]}")

def load_key_from_file(filename: str) -> Tuple[int, int]:
    """Load a key from a file"""
    with open(filename, 'r') as f:
        n = int(f.readline().strip())
        e_or_d = int(f.readline().strip())
    return (n, e_or_d)

def demo_rsa_communication():
    """Demonstrate secure communication using RSA"""
    print("RSA Encryption/Decryption Demo")
    print("-" * 50)
    
    # Initialize RSA with 2048-bit key
    rsa = RSA(2048)
    print("Generating keypair (this may take a moment)...")
    rsa.generate_keypair()
    print("Keypair generated successfully!")
    
    # Save keys to files
    save_key_to_file(rsa.public_key, "public_key.txt")
    save_key_to_file(rsa.private_key, "private_key.txt")
    print("\nKeys saved to files: public_key.txt, private_key.txt")
    
    # Example message
    message = "Hello, this is a secret message! 🔒"
    print(f"\nOriginal message: {message}")
    
    # Encrypt
    print("\nEncrypting message...")
    start_time = datetime.now()
    try:
        encrypted = rsa.encrypt(message)
        encryption_time = (datetime.now() - start_time).total_seconds()
        print(f"Encryption completed in {encryption_time:.3f} seconds")
        print(f"Encrypted message (hex): {hex(encrypted)}")
        
        # Decrypt
        print("\nDecrypting message...")
        start_time = datetime.now()
        decrypted = rsa.decrypt(encrypted)
        decryption_time = (datetime.now() - start_time).total_seconds()
        print(f"Decryption completed in {decryption_time:.3f} seconds")
        print(f"Decrypted message: {decrypted.decode('utf-8')}")
        
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    demo_rsa_communication()