import random
import math
import binascii
from sympy import isprime
from textwrap import wrap

# ================== CORE RSA FUNCTIONS ==================
def generate_large_prime(min_value=10**3, max_value=10**6):
    """Generate large random prime numbers using Miller-Rabin test"""
    while True:
        num = random.randint(min_value, max_value)
        if isprime(num):
            return num

def generate_rsa_keys(bit_length=1024):
    """Generate secure RSA keys with proper prime selection"""
    p = generate_large_prime(2**(bit_length//2-1), 2**(bit_length//2))
    q = generate_large_prime(2**(bit_length//2-1), 2**(bit_length//2))
    
    n = p * q
    phi = (p-1) * (q-1)
    
    # Find e coprime with phi
    e = 65537
    while math.gcd(e, phi) != 1:
        e += 2
    
    # Calculate d using extended Euclidean algorithm
    d = pow(e, -1, phi)
    
    return (n, e), (n, d)

def rsa_encrypt(message, public_key):
    """Encrypt message using RSA public key"""
    n, e = public_key
    message_int = bytes_to_int(message)
    if message_int >= n:
        raise ValueError("Message too long for key size")
    return pow(message_int, e, n)

def rsa_decrypt(ciphertext, private_key):
    """Decrypt ciphertext using RSA private key"""
    n, d = private_key
    decrypted_int = pow(ciphertext, d, n)
    return int_to_bytes(decrypted_int)

# ================== UTILITY FUNCTIONS ==================
def bytes_to_int(data):
    """Convert bytes to integer"""
    return int.from_bytes(data, byteorder='big')

def int_to_bytes(number):
    """Convert integer to bytes"""
    return number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')

def format_hex(data, block_size=16):
    """Format data as hexadecimal string with blocks"""
    hex_str = data.hex().upper()
    return ' '.join(wrap(hex_str, block_size))

def validate_message(message, max_bytes):
    """Validate message length for RSA constraints"""
    if len(message) > max_bytes:
        raise ValueError(f"Message exceeds maximum length of {max_bytes} bytes")
    return True

# ================== USER INTERFACE ==================
def main_menu():
    """Main user interface"""
    print("\n=== RSA Encryption System ===")
    print("1. Generate New Keys")
    print("2. Encrypt Message")
    print("3. Decrypt Message")
    print("4. Exit")
    
    while True:
        choice = input("\nSelect operation (1-4): ")
        if choice in ('1', '2', '3', '4'):
            return choice
        print("Invalid choice. Please enter 1-4.")

def handle_encryption(public_key):
    """Encryption workflow"""
    message = input("Enter message to encrypt: ").encode('utf-8')
    try:
        max_length = (public_key[0].bit_length() // 8) - 11  # PKCS#1 v1.5 padding
        validate_message(message, max_length)
        ciphertext = rsa_encrypt(message, public_key)
        print(f"\nEncrypted Data (HEX): {format_hex(int_to_bytes(ciphertext))}")
    except ValueError as e:
        print(f"Error: {e}")

def handle_decryption(private_key):
    """Decryption workflow"""
    cipher_hex = input("Enter ciphertext in HEX format: ").replace(' ', '')
    try:
        ciphertext = int.from_bytes(bytes.fromhex(cipher_hex), byteorder='big')
        plaintext = rsa_decrypt(ciphertext, private_key)
        print(f"\nDecrypted Message: {plaintext.decode('utf-8')}")
    except (ValueError, binascii.Error) as e:
        print(f"Error: {e}")

# ================== MAIN PROGRAM ==================
if __name__ == "__main__":
    public_key = None
    private_key = None
    
    while True:
        choice = main_menu()
        
        if choice == '1':
            public_key, private_key = generate_rsa_keys()
            print("\nNew Keys Generated:")
            print(f"Public Key (n): {public_key[0]}")
            print(f"Public Exponent (e): {public_key[1]}")
            print(f"Private Exponent (d): {private_key[1]}")
            
        elif choice == '2':
            if not public_key:
                print("Please generate keys first!")
                continue
            handle_encryption(public_key)
            
        elif choice == '3':
            if not private_key:
                print("Please generate keys first!")
                continue
            handle_decryption(private_key)
            
        elif choice == '4':
            print("Exiting...")
            break
