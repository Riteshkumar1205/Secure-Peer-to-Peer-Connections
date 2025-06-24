import socket
import ssl
import threading
import logging
import secrets
import argparse
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ======== SECURITY CONFIG ========
DEFAULT_PORT = 8443
CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'
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
        self.active_clients = {}
        self.setup_context()
        self.running = True

    def setup_context(self):
        """Configure TLS context with modern security settings"""
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if self.use_tls:
            self.context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
            self.context.set_ciphers(CIPHERS)
            self.context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
            self.context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            self.context.verify_mode = ssl.CERT_OPTIONAL
            self.context.check_hostname = False

    def handle_client(self, conn, addr):
        """Secure client connection handler"""
        client_id = None
        try:
            # Perform key exchange
            client_pub_bytes = conn.recv(4096)
            client_public_key = serialization.load_pem_public_key(
                client_pub_bytes, backend=default_backend()
            )
            
            # Generate server ephemeral key pair
            server_private_key = ec.generate_private_key(
                ec.SECP384R1(), default_backend()
            )
            server_public_key = server_private_key.public_key()
            
            # Send server's public key
            conn.sendall(server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
            # Derive shared secret
            shared_secret = server_private_key.exchange(
                ec.ECDH(), client_public_key
            )
            
            # Derive session key using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'secure_chat_session',
                backend=default_backend()
            )
            session_key = hkdf.derive(shared_secret)
            
            # Get client ID
            client_id = conn.recv(1024).decode().strip()
            logging.info(f"New connection from {addr} - ID: {client_id}")
            
            # Store client information
            self.active_clients[client_id] = {
                'conn': conn,
                'session_key': session_key,
                'last_active': time.time()
            }
            
            # Send welcome message
            self.send_message(conn, session_key, f"Server: Welcome {client_id}!")
            
            # Handle incoming messages
            while self.running:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                        
                    # Update last active time
                    self.active_clients[client_id]['last_active'] = time.time()
                    
                    # Decrypt and broadcast message
                    message = self.decrypt_message(data, session_key)
                    logging.info(f"Received from {client_id}: {message.decode('utf-8', errors='replace')}")
                    self.broadcast_message(client_id, message)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    logging.error(f"Error handling {client_id}: {str(e)}")
                    break
                    
        except Exception as e:
            logging.error(f"Connection error with {addr}: {str(e)}")
        finally:
            self.remove_client(client_id)

    def decrypt_message(self, data, key):
        """Decrypt message with AES-GCM"""
        if len(data) < 12 + 16:  # nonce + tag
            raise ValueError("Invalid ciphertext length")
            
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def encrypt_message(self, message, key):
        """Encrypt message with AES-GCM"""
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, message, None)
        return nonce + ciphertext

    def send_message(self, conn, key, message):
        """Encrypt and send message to client"""
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
            encrypted = self.encrypt_message(message, key)
            conn.sendall(encrypted)
            return True
        except Exception as e:
            logging.error(f"Send error: {str(e)}")
            return False

    def broadcast_message(self, sender_id, message):
        """Send message to all clients except sender"""
        if isinstance(message, bytes):
            message = message.decode('utf-8', errors='replace')
            
        formatted_msg = f"{sender_id}: {message}"
        
        for client_id, client_info in list(self.active_clients.items()):
            if client_id != sender_id:
                try:
                    self.send_message(
                        client_info['conn'],
                        client_info['session_key'],
                        formatted_msg
                    )
                except Exception as e:
                    logging.error(f"Error broadcasting to {client_id}: {str(e)}")
                    self.remove_client(client_id)

    def remove_client(self, client_id):
        """Remove client from active connections"""
        if client_id and client_id in self.active_clients:
            try:
                self.active_clients[client_id]['conn'].close()
            except:
                pass
            del self.active_clients[client_id]
            logging.info(f"Client {client_id} disconnected")
            self.broadcast_message(
                "Server", 
                f"{client_id} has left the chat"
            )

    def start(self):
        """Start the server and listen for connections"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(10)
            sock.settimeout(1)  # Allow for periodic checks

            if self.use_tls:
                sock = self.context.wrap_socket(sock, server_side=True)

            logging.info(f"Secure chat server listening on {self.host}:{self.port}")

            try:
                while self.running:
                    try:
                        conn, addr = sock.accept()
                        conn.settimeout(1)
                        client_thread = threading.Thread(
                            target=self.handle_client,
                            args=(conn, addr)
                        )
                        client_thread.daemon = True
                        client_thread.start()
                    except socket.timeout:
                        continue
                    except ssl.SSLError as e:
                        logging.error(f"SSL handshake failed: {str(e)}")
            except KeyboardInterrupt:
                logging.info("Server shutting down gracefully")
                self.running = False

# ======== USER-FRIENDLY INTERFACE ========
def print_banner():
    print(r"""
   _____ ______  _____  _    _  _____  ______ 
  / ____|  ____|/ ____|| |  | ||  __ \|  ____|
 | (___ | |__  | |     | |  | || |__) | |__   
  \___ \|  __| | |     | |  | ||  _  /|  __|  
  ____) | |____| |____ | |__| || | \ \| |____ 
 |_____/|______|\_____(_)____/ |_|  \_\______|

           🔐 Secure Chat Server v3.0
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
