import math
import time
import random
from typing import Tuple
from datetime import datetime
from rsa import RSA  # Import your RSA class from the provided code

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
        print(limit)
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

def demo_security_analysis_factorization():

    # Create an RSA instance with a smaller key_size for demonstration only
    # NOTE: Using a smaller key size to make naive factoring feasible in a demo
    rsa_small = RSA(key_size=48)  # 32 bits is extremely insecure, but let's do it for demonstration
    rsa_small.generate_keypair()

    analyzer_small = RSASecurityAnalysis(rsa_small)

    # Show naive factoring success for a small modulus
    analyzer_small.test_naive_factoring()

    


import time
import statistics

def timing_attack_demo(rsa, ciphertexts, repetitions=1000):
    """
    Perform multiple timing measurements on each ciphertext
    to demonstrate that timing could leak secrets if not 
    mitigated properly.
    """
    results = []
    for i, c in enumerate(ciphertexts):
        times = []
        for _ in range(repetitions):
            start = time.perf_counter_ns()
            _ = rsa.decrypt(c)
            end = time.perf_counter_ns()
            times.append(end - start)
        
        avg_time = statistics.mean(times)
        stdev_time = statistics.pstdev(times)
        results.append((c, avg_time, stdev_time))
    
    # Print summary
    for i, (c, avg, stdev) in enumerate(results):
        print(f"Ciphertext {i}: avg = {avg/1e6:.6f} ms, std dev = {stdev/1e6:.6f} ms")
def generate_ciphertexts(rsa: RSA):
    """
    Generate a list of ciphertexts from different plaintext messages
    to analyze potential timing differences.
    """
    plaintexts = [
        b"A",
        b"Hello",
        b"SecretMsg",
        b"12345678",
        b"abcdefg",
    ]
    
    ciphertexts = []
    for msg in plaintexts:
        c = rsa.encrypt(msg)
        ciphertexts.append(c)
    return ciphertexts

def main():
    # 1. Create RSA instance & generate keys
    rsa_instance = RSA(key_size=512)  # 512-bit for faster demo (still not secure in real world)
    rsa_instance.generate_keypair()

    # 2. Generate a list of ciphertexts
    ciphers = generate_ciphertexts(rsa_instance)
    print("Generated ciphertexts:\n", [hex(c) for c in ciphers])

    # 3. Perform timing attack demo
    timing_attack_demo(rsa_instance, ciphers, repetitions=50)

if __name__ == "__main__":
    main()
    demo_security_analysis_factorization()
