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
parser.add_argument('--no-tls', action='store_true', help='Disable TLS encryption')
parser.add_argument('-H', '--host', default='0.0.0.0', help='Server host to bind')
parser.add_argument('-p', '--port', type=int, default=8443, help='Port to listen on')
args = parser.parse_args()

# === Logging Setup ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# === TLS Configuration ===
CERTFILE = './server.crt'
KEYFILE = './server.key'
SESSION_KEY_SIZE = 32

def perform_key_exchange(conn):
    """ECDH Key Exchange"""
    try:
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

        # Derive shared session key using HKDF
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

    except Exception as e:
        logging.error(f"Key exchange failed: {e}")
        raise

def handle_client(conn, addr, use_tls):
    logging.info(f"Client connected from {addr}")
    conn.settimeout(15)  # Prevents indefinite hanging on recv

    try:
        aesgcm = perform_key_exchange(conn)
        logging.info("Key exchange complete")

        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    logging.info(f"Client {addr} disconnected")
                    break

                if len(data) < 28:  # 12-byte nonce + at least 16-byte tag
                    logging.warning(f"Malformed data from {addr}")
                    continue

                nonce = data[:12]
                ciphertext = data[12:]
                msg = aesgcm.decrypt(nonce, ciphertext, None).decode()
                logging.info(f"[{addr}] {msg}")

                # Echo back
                response = f"Echo: {msg}".encode()
                nonce = os.urandom(12)
                encrypted = aesgcm.encrypt(nonce, response, None)
                conn.sendall(nonce + encrypted)

            except socket.timeout:
                logging.warning(f"Timeout from client {addr}")
                break
            except Exception as e:
                logging.warning(f"Error during communication with {addr}: {e}")
                break

    except Exception as e:
        logging.error(f"Fatal error with client {addr}: {e}")

    finally:
        conn.close()
        logging.info(f"Connection with {addr} closed")

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((args.host, args.port))
    sock.listen(5)

    logging.info("🚀 Secure Chat Server v3.0 started")
    logging.info(f"Listening on {args.host}:{args.port} | TLS={'enabled' if not args.no_tls else 'disabled'}")

    while True:
        client_conn, client_addr = sock.accept()

        if not args.no_tls:
            try:
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
                client_conn = context.wrap_socket(client_conn, server_side=True)
            except ssl.SSLError as e:
                logging.error(f"TLS handshake failed with {client_addr}: {e}")
                client_conn.close()
                continue
            except Exception as e:
                logging.error(f"Unexpected TLS error: {e}")
                client_conn.close()
                continue

        handle_client(client_conn, client_addr, use_tls=not args.no_tls)

if __name__ == "__main__":
    main()
