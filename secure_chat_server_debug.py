#!/usr/bin/env python3
import logging
import socket
import ssl
import threading
import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# === Logging Setup ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("SecureServer")

# === TLS Config ===
CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'
DEFAULT_PORT = 8443
SESSION_KEY_SIZE = 32

def perform_key_exchange(conn, addr):
    conn.settimeout(30)
    logger.info(f"[{addr}] Waiting for client's public key...")
    client_pub_bytes = conn.recv(4096)
    if not client_pub_bytes:
        raise RuntimeError("Client public key not received")
    logger.info(f"[{addr}] Received client public key ({len(client_pub_bytes)} bytes)")

    client_pub = serialization.load_pem_public_key(client_pub_bytes, backend=default_backend())
    server_priv = ec.generate_private_key(ec.SECP384R1(), default_backend())
    server_pub = server_priv.public_key()
    server_pub_bytes = server_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.sendall(server_pub_bytes)
    logger.info(f"[{addr}] Sent server public key")

    shared_secret = server_priv.exchange(ec.ECDH(), client_pub)
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_SIZE,
        salt=None,
        info=b'secure_chat_session',
        backend=default_backend()
    ).derive(shared_secret)
    logger.info(f"[{addr}] Session key derived")

    return AESGCM(session_key)

def handle_client(conn, addr):
    logger.info(f"[{addr}] Connected")
    try:
        aesgcm = perform_key_exchange(conn, addr)
        logger.info(f"[{addr}] Key exchange complete")

        while True:
            conn.settimeout(None)
            data = conn.recv(4096)
            if not data:
                break

            try:
                nonce = data[:12]
                ciphertext = data[12:]
                msg = aesgcm.decrypt(nonce, ciphertext, None).decode()
                logger.info(f"[{addr}] Decrypted message: {msg}")

                response = f"Echo: {msg}".encode()
                nonce2 = os.urandom(12)
                encrypted = aesgcm.encrypt(nonce2, response, None)
                conn.sendall(nonce2 + encrypted)
            except Exception as e:
                logger.warning(f"[{addr}] Decryption error: {e}")

    except Exception as e:
        logger.error(f"[{addr}] Connection error: {e}")
    finally:
        conn.close()
        logger.info(f"[{addr}] Disconnected")

def main():
    bindsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsock.bind(('0.0.0.0', DEFAULT_PORT))
    bindsock.listen(5)
    logger.info(f"Secure Server listening on 0.0.0.0:{DEFAULT_PORT}")

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    while True:
        newsock, addr = bindsock.accept()
        try:
            conn = ssl_context.wrap_socket(newsock, server_side=True)
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except ssl.SSLError as e:
            logger.error(f"[{addr}] TLS handshake failed: {e}")
            newsock.close()

if __name__ == '__main__':
    main()
