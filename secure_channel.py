import secrets
from math import gcd
from sympy import isprime, primitive_root

class ElGamal:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.public_key, self.private_key = self.generate_keys()

    def generate_keys(self):
        """Generate secure ElGamal keys"""
        # Generate large prime
        while True:
            q = secrets.randbits(self.key_size)
            if isprime(q) and q > 2**self.key_size:
                break
        
        # Find primitive root
        a = primitive_root(q)
        
        # Generate private key
        XA = secrets.randbelow(q-2) + 1
        
        # Calculate public key
        YA = pow(a, XA, q)
        
        return {'q': q, 'a': a, 'YA': YA}, {'XA': XA, 'q': q}

    def encrypt(self, message):
        """Encrypt message using public key"""
        q = self.public_key['q']
        a = self.public_key['a']
        YA = self.public_key['YA']
        
        if not isinstance(message, bytes):
            message = message.encode('utf-8')
        
        # Convert message to integer
        m = int.from_bytes(message, 'big')
        if m >= q:
            raise ValueError("Message too large for current key size")
        
        # Generate ephemeral key
        k = secrets.randbelow(q-2) + 1
        
        # Compute shared secret
        K = pow(YA, k, q)
        
        # Compute cipher components
        C1 = pow(a, k, q)
        C2 = (K * m) % q
        
        return (C1, C2)

    def decrypt(self, ciphertext):
        """Decrypt ciphertext using private key"""
        C1, C2 = ciphertext
        XA = self.private_key['XA']
        q = self.private_key['q']
        
        # Compute shared secret
        K = pow(C1, XA, q)
        
        # Modular inverse using extended Euclidean
        kinv = pow(K, -1, q)
        
        # Recover message
        m = (C2 * kinv) % q
        
        # Convert back to bytes
        byte_length = (m.bit_length() + 7) // 8
        return m.to_bytes(byte_length, 'big').decode('utf-8')

# ================== USAGE EXAMPLE ==================
if __name__ == "__main__":
    # Initialize cryptosystem
    elgamal = ElGamal()
    
    # Encryption
    message = "Secret message"
    ciphertext = elgamal.encrypt(message)
    print(f"Ciphertext: {ciphertext}")
    
    # Decryption
    decrypted = elgamal.decrypt(ciphertext)
    print(f"Decrypted: {decrypted}")
