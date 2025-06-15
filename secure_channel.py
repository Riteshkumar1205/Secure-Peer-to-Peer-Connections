import secrets
from sympy import isprime, nextprime, primitive_root


class ElGamal:
    def __init__(self, key_size=256):  # 256-bit for demo; increase for real security
        self.key_size = key_size
        self.public_key, self.private_key = self.generate_keys()

    def generate_keys(self):
        """Generate secure ElGamal keys"""
        # Step 1: Generate a large prime q
        while True:
            candidate = secrets.randbits(self.key_size)
            q = nextprime(candidate)
            if isprime(q):
                break

        # Step 2: Find primitive root a modulo q
        a = primitive_root(q)

        # Step 3: Choose private key XA
        XA = secrets.randbelow(q - 2) + 1

        # Step 4: Compute public key YA = a^XA mod q
        YA = pow(a, XA, q)

        return {'q': q, 'a': a, 'YA': YA}, {'XA': XA, 'q': q}

    def encrypt(self, message):
        """Encrypt message using public key"""
        q, a, YA = self.public_key['q'], self.public_key['a'], self.public_key['YA']

        if not isinstance(message, bytes):
            message = message.encode('utf-8')

        m = int.from_bytes(message, 'big')
        if m >= q:
            raise ValueError("Message too large for current key size.")

        k = secrets.randbelow(q - 2) + 1
        C1 = pow(a, k, q)
        K = pow(YA, k, q)
        C2 = (K * m) % q

        return (C1, C2)

    def decrypt(self, ciphertext):
        """Decrypt ciphertext using private key"""
        C1, C2 = ciphertext
        XA, q = self.private_key['XA'], self.private_key['q']

        K = pow(C1, XA, q)
        K_inv = pow(K, -1, q)  # Modular inverse
        m = (C2 * K_inv) % q

        byte_len = (m.bit_length() + 7) // 8
        try:
            return m.to_bytes(byte_len, 'big').decode('utf-8')
        except UnicodeDecodeError:
            return "[Decryption error: invalid UTF-8 message]"

# ================== USAGE EXAMPLE ==================
if __name__ == "__main__":
    elgamal = ElGamal()

    message = "Secret message"
    print(f"Original message: {message}")

    ciphertext = elgamal.encrypt(message)
    print(f"Ciphertext: {ciphertext}")

    decrypted = elgamal.decrypt(ciphertext)
    print(f"Decrypted message: {decrypted}")
