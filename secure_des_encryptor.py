import binascii
import math
import secrets
import os
import hmac
import hashlib
from cryptography.hazmat.primitives import padding

# --- UTILITY FUNCTIONS ---
def str2hex(word):
    word_2byte = bytes(word, 'ascii')
    return binascii.hexlify(word_2byte).decode().upper()

def hex2bin(s):
    mp = {'0': "0000", '1': "0001", '2': "0010", '3': "0011",
          '4': "0100", '5': "0101", '6': "0110", '7': "0111",
          '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
          'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"}
    return ''.join(mp[ch] for ch in s)

def bin2hex(s):
    mp = {"0000": '0', "0001": '1', "0010": '2', "0011": '3',
          "0100": '4', "0101": '5', "0110": '6', "0111": '7',
          "1000": '8', "1001": '9', "1010": 'A', "1011": 'B',
          "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'}
    return ''.join(mp[s[i:i+4]] for i in range(0, len(s), 4))

def bin2dec(binary):
    decimal, i = 0, 0
    while binary != 0:
        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary // 10
        i += 1
    return decimal

def dec2bin(num):
    res = bin(num).replace("0b", "")
    if len(res) % 4 != 0:
        div = len(res) / 4
        div = int(div)
        counter = (4 * (div + 1)) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res

def permute(k, arr, n):
    permutation = ""
    for i in range(n):
        permutation += k[arr[i] - 1]
    return permutation

def shift_left(k, nth_shifts):
    s = ""
    for i in range(nth_shifts):
        for j in range(1, len(k)):
            s += k[j]
        s += k[0]
        k = s
        s = ""
    return k

def xor(a, b):
    ans = ""
    for i in range(len(a)):
        ans += "0" if a[i] == b[i] else "1"
    return ans

# --- SECURITY ENHANCEMENTS ---
def generate_secure_key():
    """Generate cryptographically secure 64-bit (8-byte) key"""
    return secrets.token_hex(8).upper()

def validate_key(key):
    """Validate key meets security requirements"""
    if len(key) != 16 or not all(c in '0123456789ABCDEF' for c in key):
        raise ValueError("Key must be 16-character hexadecimal (64-bit)")
    return key

def apply_pkcs7_padding(data, block_size=8):
    """Apply PKCS#7 padding for block alignment"""
    padder = padding.PKCS7(block_size * 8).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def remove_pkcs7_padding(data, block_size=8):
    """Remove PKCS#7 padding"""
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def generate_hmac(key, data):
    """Generate HMAC for data integrity"""
    return hmac.new(bytes.fromhex(key), data, hashlib.sha256).digest()

def verify_hmac(key, data, mac):
    """Verify HMAC for data integrity"""
    expected_mac = generate_hmac(key, data)
    return hmac.compare_digest(mac, expected_mac)

# --- DES CORE FUNCTIONS ---
def encrypt_block(pt, rkb, rk, initial_perm, exp_d, per, sbox, final_perm):
    pt = hex2bin(pt)
    pt = permute(pt, initial_perm, 64)
    left = pt[0:32]
    right = pt[32:64]
    for i in range(16):
        right_expanded = permute(right, exp_d, 48)
        xor_x = xor(right_expanded, rkb[i])
        sbox_str = ""
        for j in range(8):
            row = bin2dec(int(xor_x[j*6] + xor_x[j*6+5]))
            col = bin2dec(int(xor_x[j*6+1] + xor_x[j*6+2] + xor_x[j*6+3] + xor_x[j*6+4]))
            val = sbox[j][row][col]
            sbox_str += dec2bin(val)
        sbox_str = permute(sbox_str, per, 32)
        result = xor(left, sbox_str)
        left = result
        if i != 15:
            left, right = right, left
    combine = left + right
    cipher_text = permute(combine, final_perm, 64)
    return cipher_text

def decrypt_block(ct, rkb, rk, initial_perm, exp_d, per, sbox, final_perm):
    # DES decryption is same as encryption, but round keys are used in reverse order
    return encrypt_block(ct, rkb[::-1], rk[::-1], initial_perm, exp_d, per, sbox, final_perm)

def generate_round_keys(key, keyp, shift_table, key_comp):
    key = hex2bin(key)
    key = permute(key, keyp, 56)
    left = key[0:28]
    right = key[28:56]
    rkb, rk = [], []
    for i in range(16):
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])
        combine_str = left + right
        round_key = permute(combine_str, key_comp, 48)
        rkb.append(round_key)
        rk.append(bin2hex(round_key))
    return rkb, rk

# --- DES TABLES ---
initial_perm = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
                62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
                57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
                61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
exp_d = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
         16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
per = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,
       19,13,30,6,22,11,4,25]
sbox = [[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
        [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
        [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
        [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
        [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
        [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
        [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
        [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]]
final_perm = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
              38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
              36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
              34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
keyp = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,
        60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
shift_table = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
key_comp = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
            41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]

# --- CBC MODE AND HMAC INTEGRATION ---
def des_encrypt_cbc(pt, key, iv):
    # Pad plaintext
    pt_padded = apply_pkcs7_padding(pt.encode('ascii'))
    # Convert to hex blocks
    blocks = [pt_padded[i:i+8] for i in range(0, len(pt_padded), 8)]
    rkb, rk = generate_round_keys(key, keyp, shift_table, key_comp)
    ct_blocks = []
    previous_block = iv
    for block in blocks:
        # XOR with previous ciphertext block (or IV)
        block_bytes = bytes([b ^ p for b, p in zip(block, previous_block)])
        block_hex = binascii.hexlify(block_bytes).decode().upper()
        ct_block = bin2hex(encrypt_block(block_hex, rkb, rk, initial_perm, exp_d, per, sbox, final_perm))
        ct_blocks.append(ct_block)
        previous_block = bytes.fromhex(ct_block)
    ciphertext = b''.join([bytes.fromhex(b) for b in ct_blocks])
    # Add HMAC
    mac = generate_hmac(key, ciphertext)
    return iv + ciphertext + mac

def des_decrypt_cbc(ct_with_iv_mac, key):
    # Split IV, ciphertext, and MAC
    iv = ct_with_iv_mac[:8]
    mac = ct_with_iv_mac[-32:]
    ciphertext = ct_with_iv_mac[8:-32]
    # Verify HMAC
    if not verify_hmac(key, ciphertext, mac):
        raise ValueError("HMAC verification failed: data integrity compromised")
    # Split into blocks
    blocks = [ciphertext[i:i+8] for i in range(0, len(ciphertext), 8)]
    rkb, rk = generate_round_keys(key, keyp, shift_table, key_comp)
    pt_blocks = []
    previous_block = iv
    for block in blocks:
        block_hex = binascii.hexlify(block).decode().upper()
        decrypted_block = bin2hex(decrypt_block(block_hex, rkb, rk, initial_perm, exp_d, per, sbox, final_perm))
        decrypted_bytes = bytes.fromhex(decrypted_block)
        # XOR with previous ciphertext block (or IV)
        pt_block = bytes([b ^ p for b, p in zip(decrypted_bytes, previous_block)])
        pt_blocks.append(pt_block)
        previous_block = block
    plaintext_padded = b''.join(pt_blocks)
    # Remove padding
    plaintext = remove_pkcs7_padding(plaintext_padded)
    return plaintext.decode('ascii')

# --- USER INTERFACE ---
def main():
    print("DES Encryption/Decryption Tool (CBC Mode, HMAC)")
    print("1. Encrypt")
    print("2. Decrypt")
    choice = input("Choose operation (1/2): ")

    if choice == "1":
        pt = input("Enter plaintext: ")
        key = input("Enter 16-character hex key (or press enter to generate): ")
        if not key:
            key = generate_secure_key()
            print("Generated key:", key)
        else:
            key = validate_key(key)
        iv = os.urandom(8)
        cipher = des_encrypt_cbc(pt, key, iv)
        print("Ciphertext with IV and HMAC (hex):", cipher.hex())
        print("Key:", key)
    elif choice == "2":
        cipher_hex = input("Enter ciphertext (hex, with IV and HMAC): ")
        key = input("Enter 16-character hex key: ")
        key = validate_key(key)
        cipher = bytes.fromhex(cipher_hex)
        plaintext = des_decrypt_cbc(cipher, key)
        print("Plaintext:", plaintext)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
