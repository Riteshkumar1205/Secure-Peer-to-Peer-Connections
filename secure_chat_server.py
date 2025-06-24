import socket
import ssl
import argparse
import logging
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# === Argument Parsing ===
parser = argparse.ArgumentParser()
parser.add_argument('--no-tls', action='store_true', help='Disable TLS')
parser.add_argument('-H', '--host', default='0.0.0.0')
parser.add_argument('-p', '--port', type=int, default=8443)
args = parser.parse_args()

# === Logging Setup ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# === TLS Config ===
CERTFILE = './server.crt'
KEYFILE = './server.key'
SESSION_KEY_SIZE = 32

def perform_key_exchange(conn):
    """ECDH Key Exchange"""
    # Receive client's public key
    client_pub_bytes = conn.recv(4096)
    client_pub = serialization.load_pem_public_key(client_pub_bytes, backend=default_backend())
    logging.info("Received client's public key")

    # Generate server key pair
    server_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
    server_public = server_private.public_key()

    # Send public key to client
    server_pub_bytes = server_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.sendall(server_pub_bytes)
    logging.info("Sent server public key")

    # Derive shared secret and session key
    shared_secret = server_private.exchange(ec.ECDH(), client_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_SIZE,
        salt=None,
        info=b'secure_chat_session',
        backend=default_backend()
    )
    session_key = hkdf.derive(shared_secret)
    return AESGCM(session_key)

def handle_client(conn, addr, use_tls):
    logging.info(f"Client connected: {addr}")
    try:
        aesgcm = perform_key_exchange(conn)
        logging.info("Key exchange complete")

        while True:
            data = conn.recv(4096)
            if not data:
                break
            nonce = data[:12]
            ciphertext = data[12:]
            try:
                msg = aesgcm.decrypt(nonce, ciphertext, None).decode()
                logging.info(f"[{addr}] {msg}")

                # Echo back (encrypted)
                response = f"Echo: {msg}".encode()
                nonce = os.urandom(12)
                encrypted = aesgcm.encrypt(nonce, response, None)
                conn.sendall(nonce + encrypted)
            except Exception as e:
                logging.warning(f"Decryption failed: {e}")
    except Exception as e:
        logging.error(f"Error with {addr}: {e}")
    finally:
        conn.close()
        logging.info(f"Disconnected: {addr}")

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((args.host, args.port))
    sock.listen(5)

    logging.info("Secure Chat Server v3.0")
    logging.info(f"Listening on {args.host}:{args.port}")

    while True:
        client_conn, client_addr = sock.accept()

        if not args.no_tls:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
            try:
                client_conn = context.wrap_socket(client_conn, server_side=True)
            except ssl.SSLError as e:
                logging.error(f"TLS handshake failed: {e}")
                client_conn.close()
                continue

        handle_client(client_conn, client_addr, use_tls=not args.no_tls)

if __name__ == "__main__":
    main()
