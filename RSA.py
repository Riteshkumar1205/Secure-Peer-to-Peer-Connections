#!/usr/bin/env python3
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, sniff
from threading import Thread, Lock
import pandas as pd
import time
import os
import sys
import platform
import random
import math
import binascii
from sympy import isprime
from textwrap import wrap

# ================== GLOBAL VARIABLES ==================
access_points = pd.DataFrame(columns=["BSSID", "SSID", "Signal(dBm)", "Channel", "Security"])
access_points.set_index("BSSID", inplace=True)
access_points_lock = Lock()

public_key = None
private_key = None
interface = "wlan0mon"

# ================== DEPENDENCY CHECKS ==================
try:
    import pandas as pd
except ImportError:
    print("Error: Install pandas with 'pip install pandas'")
    sys.exit(1)

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, sniff
except ImportError:
    print("Error: Install scapy with 'pip install scapy'")
    sys.exit(1)

try:
    from sympy import isprime
except ImportError:
    print("Error: Install sympy with 'pip install sympy'")
    sys.exit(1)

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

def clear_screen():
    """Clear terminal screen cross-platform"""
    os.system("cls" if platform.system() == "Windows" else "clear")

# ================== WIFI SCANNER FUNCTIONS ==================
def data_extraction(packet):
    """Extract info from beacon frames"""
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        try:
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore') if packet[Dot11Elt].info else "<Hidden>"
        except Exception:
            ssid = "<Error>"

        try:
            signal = packet.dBm_AntSignal
        except Exception:
            signal = "N/A"

        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel", "N/A")
        security = ", ".join(stats.get("crypto", []))
        
        with access_points_lock:
            access_points.loc[bssid] = (ssid, signal, channel, security)

def channel_hopper():
    """Cycle through channels 1-14"""
    while True:
        for ch in range(1, 14):
            os.system(f"iw dev {interface} set channel {ch}")
            time.sleep(0.5)

def view_networks():
    """Display current WiFi networks"""
    clear_screen()
    print(r'''
╭────────────────────────────────────────────────────────────────────────────╮
│ ██╗    ██╗██╗███████╗██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗     │
│ ██║    ██║██║██╔════╝██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║     │
│ ██║ █╗ ██║██║█████╗  ██║    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║     │
│ ██║███╗██║██║██╔══╝  ██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║     │
│ ╚███╔███╔╝██║██║     ██║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║     │
│  ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝     │
├─────────────── WiFi Scanner & RSA Encryption Toolkit v3.0 ────────────────┤
''')
    with access_points_lock:
        with pd.option_context('display.max_rows', None, 'display.width', None):
            print(access_points.sort_values(by="Signal(dBm)", ascending=False))
    print("\nPress Enter to return to menu...", end="")
    input()

# ================== RSA OPERATIONS ==================
def handle_key_generation():
    """Generate and display RSA keys"""
    global public_key, private_key
    public_key, private_key = generate_rsa_keys()
    print("\n[+] New RSA Keys Generated:")
    print(f"Public Key (n):\n{public_key[0]}")
    print(f"Public Exponent (e): {public_key[1]}")
    print(f"Private Exponent (d):\n{private_key[1]}")

def handle_encryption():
    """Encryption workflow"""
    if not public_key:
        print("[!] Please generate keys first!")
        return
        
    message = input("\nEnter message to encrypt: ").encode('utf-8')
    try:
        max_length = (public_key[0].bit_length() // 8) - 11
        if len(message) > max_length:
            raise ValueError(f"Message exceeds maximum length of {max_length} bytes")
            
        ciphertext = rsa_encrypt(message, public_key)
        hex_cipher = int_to_bytes(ciphertext).hex().upper()
        formatted = ' '.join([hex_cipher[i:i+4] for i in range(0, len(hex_cipher), 4)])
        
        print("\n[+] Encrypted Data (HEX):")
        print(formatted)
    except ValueError as e:
        print(f"[!] Error: {e}")

def handle_decryption():
    """Decryption workflow"""
    if not private_key:
        print("[!] Please generate keys first!")
        return
        
    cipher_hex = input("\nEnter ciphertext in HEX format: ").replace(' ', '')
    try:
        if not all(c in '0123456789ABCDEFabcdef' for c in cipher_hex):
            raise ValueError("Invalid HEX characters detected")
            
        ciphertext = int.from_bytes(bytes.fromhex(cipher_hex), byteorder='big')
        plaintext = rsa_decrypt(ciphertext, private_key)
        
        print("\n[+] Decrypted Message:")
        print(plaintext.decode('utf-8'))
    except (ValueError, binascii.Error) as e:
        print(f"[!] Error: {e}")
    except UnicodeDecodeError:
        print("[!] Error: Decrypted data is not valid UTF-8")

# ================== MAIN MENU ==================
def main_menu():
    """Main user interface"""
    clear_screen()
    print(r'''
╭────────────────────────────────────────────────────────────────────────────╮
│ ██╗    ██╗██╗███████╗██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗     │
│ ██║    ██║██║██╔════╝██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║     │
│ ██║ █╗ ██║██║█████╗  ██║    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║     │
│ ██║███╗██║██║██╔══╝  ██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║     │
│ ╚███╔███╔╝██║██║     ██║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║     │
│  ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝     │
├─────────────── WiFi Scanner & RSA Encryption Toolkit v3.0 ────────────────┤
│                                                                           │
│ 1. View WiFi Networks         3. Encrypt Message                          │
│ 2. Generate RSA Keys          4. Decrypt Message                          │
│ 5. Exit                                                                   │
╰────────────────────────────────────────────────────────────────────────────╯
''')
    return input("\nSelect operation (1-5): ")

# ================== MAIN PROGRAM ==================
if __name__ == "__main__":
    # Start WiFi scanning threads
    Thread(target=channel_hopper, daemon=True).start()
    Thread(target=lambda: sniff(prn=data_extraction, iface=interface, store=0), daemon=True).start()

    # Main menu loop
    while True:
        choice = main_menu()
        
        if choice == '1':
            view_networks()
        elif choice == '2':
            handle_key_generation()
            input("\nPress Enter to continue...")
        elif choice == '3':
            handle_encryption()
            input("\nPress Enter to continue...")
        elif choice == '4':
            handle_decryption()
            input("\nPress Enter to continue...")
        elif choice == '5':
            print("\n[+] Exiting...")
            break
        else:
            print("[!] Invalid selection. Please choose 1-5.")
            time.sleep(1)
