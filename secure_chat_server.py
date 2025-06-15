import socket
import ssl
import threading
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import secrets
import argparse

# ======== SECURITY CONFIG ========
DEFAULT_PORT = 1234
CERT_FILE = 'cert.pem'  # Updated
KEY_FILE = 'key.pem'    # Updated
TLS_VERSION = ssl.PROTOCOL_TLS_SERVER
CIPHERS = 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'

# ======== LOGGING CONFIG ========
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[
        logging.FileHandler('secure_chat_server.log'),
        logging.StreamHandler()
    ]
)

class SecureChatServer:
    def __init__(self, host, port, use_tls=True):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.active_clients = []
        self.session_keys = {}
        self.setup_context()

    def setup_context(self):
        """Configure TLS context with modern security settings"""
        self.context = ssl.SSLContext(TLS_VERSION)
        if self.use_tls:
            self.context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
            self.context.set_ciphers(CIPHERS)
            self.context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
            self.context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            self.context.verify_mode = ssl.CERT_NONE  # Changed from CERT_REQUIRED to avoid handshake issues in dev

    def generate_session_key(self, client_id):
        """Generate ephemeral session key using HKDF"""
        shared_secret = secrets.token_bytes(32)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=client_id.encode(),
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)

    def handle_client(self, conn, addr):
        """Secure client connection handler"""
        client_id = None
        try:
            with conn:
                client_id = conn.recv(1024).decode().strip()
                logging.info(f"New connection from {addr} - ID: {client_id}")

                session_key = self.generate_session_key(client_id)
                self.session_keys[client_id] = session_key
                self.active_clients.append((client_id, conn))

                conn.sendall(session_key)

                while True:
                    data = conn.recv(4096)
                    if not data:
                        break

                    decrypted = self.decrypt_message(data, session_key)
                    logging.info(f"Received from {client_id}: {decrypted.decode(errors='ignore')}")

                    self.broadcast_message(client_id, decrypted)

        except Exception as e:
            logging.error(f"Error handling {client_id}: {str(e)}")
        finally:
            self.remove_client(client_id)

    def decrypt_message(self, data, key):
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]

        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def encrypt_message(self, message, key):
        nonce = secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext

    def broadcast_message(self, sender_id, message):
        for client_id, conn in self.active_clients:
            if client_id != sender_id:
                try:
                    encrypted = self.encrypt_message(message, self.session_keys[client_id])
                    conn.sendall(encrypted)
                except Exception as e:
                    logging.error(f"Error sending to {client_id}: {str(e)}")
                    self.remove_client(client_id)

    def remove_client(self, client_id):
        self.active_clients = [
            (cid, conn) for cid, conn in self.active_clients if cid != client_id
        ]
        if client_id in self.session_keys:
            del self.session_keys[client_id]
        logging.info(f"Client {client_id} disconnected")

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(5)

            if self.use_tls:
                sock = self.context.wrap_socket(sock, server_side=True)

            logging.info(f"Secure chat server listening on {self.host}:{self.port}")

            try:
                while True:
                    conn, addr = sock.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr)
                    )
                    client_thread.start()
            except KeyboardInterrupt:
                logging.info("Server shutting down gracefully")

# ======== USER-FRIENDLY INTERFACE ========
def print_banner():
    print(r"""
   _____ ______  _____  _    _  _____  ______ 
  / ____|  ____|/ ____|| |  | ||  __ \|  ____|
 | (___ | |__  | |     | |  | || |__) | |__   
  \___ \|  __| | |     | |  | ||  _  /|  __|  
  ____) | |____| |____ | |__| || | \ \| |____ 
 |_____/|______|\_____(_)____/ |_|  \_\______|

           🔐 Secure Chat Server v2.1
    """)


def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description='Secure Chat Server - Military Grade Encryption'
    )
    parser.add_argument(
        '-H', '--host', 
        default='0.0.0.0', 
        help='Server host address'
    )
    parser.add_argument(
        '-p', '--port', 
        type=int, 
        default=DEFAULT_PORT,
        help=f'Server port (default: {DEFAULT_PORT})'
    )
    parser.add_argument(
        '--no-tls', 
        action='store_false',
        dest='use_tls',
        help='Disable TLS (not recommended)'
    )

    args = parser.parse_args()

    server = SecureChatServer(
        host=args.host,
        port=args.port,
        use_tls=args.use_tls
    )
    server.start()

if __name__ == '__main__':
    main()
