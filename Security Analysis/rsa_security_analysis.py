import math
import time
import random
from typing import Tuple

class RSASecurityAnalysis:
    """
    Class for demonstrating naive factoring of small RSA moduli and
    a simple timing-attack measurement on RSA decryption.
    """
    def __init__(self, rsa):
        """
        Args:
            rsa: An instance of the RSA class (from your provided RSA implementation).
        """
        self.rsa = rsa

    def naive_factor(self, n: int) -> Tuple[int, int]:
        """
        Naive approach to factor the RSA modulus n. 
        This will ONLY work feasibly for small n.

        Args:
            n (int): RSA modulus to factor.

        Returns:
            (p, q) where p and q are prime factors of n.
        """
        # Very naive approach: try dividing n by every odd number
        # from 3 up to sqrt(n). This is extremely slow for large n.
        limit = int(math.isqrt(n)) + 1
        for i in range(3, limit, 2):
            if n % i == 0:
                return i, n // i
        
        # If we don't find factors, return None
        return None, None

    def test_naive_factoring(self):
        """
        Demonstrate naive factoring on the RSA instance's modulus (self.rsa.public_key[0]).
        WARNING: This only works in reasonable time if n is small (e.g., key_size <= 32 or 64 bits).
        """
        n, _ = self.rsa.public_key  # n = p*q
        print("Testing naive factoring on the RSA modulus...")

        # For large n (e.g. 2048 bits), this will be infeasible in practice.
        p, q = self.naive_factor(n)
        if p is None or q is None:
            print("Naive factoring failed (n too large or factors not found).")
        else:
            print(f"Naive factoring succeeded: p = {p}, q = {q}")

    def timing_attack_simulation(self, test_ciphertexts):
        """
        Demonstrate a simple timing measurement for RSA decryption to see if 
        any noticeable differences appear.

        Args:
            test_ciphertexts (list): A list of integers representing ciphertexts.
        """
        print("\nTiming Attack Simulation:")
        times = []
        for cipher in test_ciphertexts:
            start = time.time()
            _ = self.rsa.decrypt(cipher)  # Decrypt the message
            end = time.time()
            duration = end - start
            times.append(duration)
            print(f"Cipher: {hex(cipher)} | Decryption time: {duration:.6f} seconds")

        print("\nDecryption timing summary:")
        for i, duration in enumerate(times):
            print(f"Ciphertext {i}: {duration:.6f}s")

def demo_security_analysis():
    from datetime import datetime
    from rsa import RSA  # Import your RSA class from the provided code

    # Create an RSA instance with a smaller key_size for demonstration only
    # NOTE: Using a smaller key size to make naive factoring feasible in a demo
    rsa_small = RSA(key_size=32)  # 32 bits is extremely insecure, but let's do it for demonstration
    rsa_small.generate_keypair()

    analyzer_small = RSASecurityAnalysis(rsa_small)

    # Show naive factoring success for a small modulus
    analyzer_small.test_naive_factoring()

    # Show timing attack simulation
    # Let's encrypt some small messages as ciphertext
    messages = [b"A", b"B", b"C", b"D", b"E"]
    ciphertexts = []
    for m in messages:
        cipher = rsa_small.encrypt(m)
        ciphertexts.append(cipher)

    analyzer_small.timing_attack_simulation(ciphertexts)

if __name__ == "__main__":
    demo_security_analysis()
