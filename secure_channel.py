import secrets
from sympy import isprime, nextprime
from math import gcd
import sys

class ElGamal:
    def __init__(self, key_size=256):
        self.key_size = key_size
        self.public_key, self.private_key = self.generate_keys()

    def generate_safe_prime(self):
        """Generate a safe prime (p = 2q + 1 where q is prime)"""
        while True:
            # Generate random prime candidate
            candidate = secrets.randbits(self.key_size)
            q = nextprime(candidate)
            
            # Check if 2q+1 is prime
            p = 2 * q + 1
            if p.bit_length() == self.key_size and isprime(p):
                return p, q

    def find_primitive_root(self, p, q):
        """Efficiently find a primitive root modulo p for safe prime"""
        # Factors of p-1 are 2 and q (since p = 2q+1)
        factors = [2, q]
        
        while True:
            g = secrets.randbelow(p - 2) + 1
            # Check if g is primitive root
            if all(pow(g, (p-1)//factor, p) != 1 for factor in factors):
                return g

    def generate_keys(self):
        """Generate secure ElGamal keys using safe primes"""
        p, q = self.generate_safe_prime()
        a = self.find_primitive_root(p, q)
        
        # Choose private key (1 < XA < p-1)
        XA = secrets.randbelow(p - 2) + 1
        YA = pow(a, XA, p)
        
        return {'p': p, 'a': a, 'YA': YA}, {'XA': XA, 'p': p}

    def encrypt(self, message):
        """Encrypt message using public key"""
        p, a, YA = self.public_key['p'], self.public_key['a'], self.public_key['YA']
        
        # Convert message to integer
        if not isinstance(message, bytes):
            message = message.encode('utf-8')
        m = int.from_bytes(message, 'big')
        
        # Validate message size
        if m >= p:
            raise ValueError(f"Message too large for key size (max {p.bit_length()-1} bits)")
        
        # Encryption
        k = secrets.randbelow(p - 2) + 1
        C1 = pow(a, k, p)
        K = pow(YA, k, p)
        C2 = (K * m) % p
        
        return (C1, C2)

    def decrypt(self, ciphertext):
        """Decrypt ciphertext using private key"""
        C1, C2 = ciphertext
        XA, p = self.private_key['XA'], self.private_key['p']
        
        # Compute shared secret
        K = pow(C1, XA, p)
        
        # Modular inverse for decryption
        K_inv = pow(K, -1, p)
        m = (C2 * K_inv) % p
        
        # Convert back to bytes
        byte_len = (m.bit_length() + 7) // 8
        decrypted_bytes = m.to_bytes(byte_len, 'big')
        
        # Try UTF-8 decoding, return bytes if fails
        try:
            return decrypted_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return decrypted_bytes

# ================== USAGE EXAMPLE ==================
if __name__ == "__main__":
    # Use 128-bit keys for faster demo while maintaining security
    elgamal = ElGamal(128)

    message = "Secret message"
    print(f"Original message: {message}")

    try:
        ciphertext = elgamal.encrypt(message)
        print(f"Ciphertext (C1, C2): {ciphertext}")
        
        decrypted = elgamal.decrypt(ciphertext)
        print(f"Decrypted message: {decrypted}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
