# secure_chat_client.py
import sys
import os
import socket
import ssl
import threading
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Platform detection
PLATFORM = sys.platform
IS_MOBILE = False

# Conditional UI imports
if PLATFORM == 'android':
    IS_MOBILE = True
    from kivy.app import App
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.textinput import TextInput
    from kivy.uix.button import Button
    from kivy.uix.label import Label
    from kivy.uix.scrollview import ScrollView
    from kivy.core.window import Window
else:
    import tkinter as tk
    from tkinter import scrolledtext, messagebox, font

# ======== SECURITY CONFIG ========
DEFAULT_PORT = 8443
CERT_FILE = './server.crt'
SESSION_KEY_SIZE = 32  # 256-bit

class SecureChatCore:
    def __init__(self, ui_callback=None):
        self.ui_callback = ui_callback
        self.security_context = {
            'aes_key': None,
            'sequence': 0
        }
        self.host = None
        self.port = DEFAULT_PORT
        self.connected = False
        self.setup_connection()

    def log(self, message):
        """Log messages to console and UI if available"""
        timestamp = time.strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}"
        print(formatted)
        if self.ui_callback:
            self.ui_callback(formatted)

    def setup_connection(self):
        try:
            self.host = input("Enter server IP (default 127.0.0.1): ") or "127.0.0.1"
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.load_verify_locations(CERT_FILE)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)  # 10-second timeout
            
            self.secure_sock = context.wrap_socket(
                self.sock, server_hostname=self.host
            )

            self.log(f"Connecting to {self.host}:{self.port}...")
            self.secure_sock.connect((self.host, self.port))
            self.log("SSL connection established")
            
            # Perform ECDH key exchange
            self.perform_key_exchange()
            self.connected = True
        except socket.timeout:
            self.log("Connection timed out")
            raise RuntimeError("Connection to server timed out")
        except socket.gaierror as e:
            self.log(f"Failed to resolve host '{self.host}': {e}")
            raise RuntimeError(f"Host resolution failed: {e}")
        except ssl.SSLCertVerificationError as e:
            self.log(f"Certificate verification failed: {e}")
            raise RuntimeError("Server certificate is invalid")
        except Exception as e:
            self.log(f"Connection failed: {str(e)}")
            raise RuntimeError(f"Connection failed: {str(e)}")

    def perform_key_exchange(self):
        """Perform ECDH key exchange for perfect forward secrecy"""
        # Generate ephemeral ECDH key pair
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key = private_key.public_key()
        
        # Serialize public key and send to server
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.secure_sock.sendall(pub_bytes)
        self.log("Sent public key to server")
        
        # Receive server's public key
        server_pub_bytes = self.secure_sock.recv(4096)
        server_public_key = serialization.load_pem_public_key(
            server_pub_bytes, backend=default_backend()
        )
        self.log("Received server's public key")
        
        # Derive shared secret
        shared_secret = private_key.exchange(ec.ECDH(), server_public_key)
        
        # Derive session keys using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=SESSION_KEY_SIZE,
            salt=None,
            info=b'secure_chat_session',
            backend=default_backend()
        )
        session_key = hkdf.derive(shared_secret)
        
        self.security_context['aes_key'] = session_key
        self.log("Session keys established")

    def encrypt_message(self, plaintext):
        """Encrypt message with AES-GCM"""
        if not self.security_context['aes_key']:
            raise RuntimeError("Encryption key not established")
            
        aesgcm = AESGCM(self.security_context['aes_key'])
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt_message(self, data):
        """Decrypt message with AES-GCM"""
        if not self.security_context['aes_key']:
            raise RuntimeError("Decryption key not established")
            
        if len(data) < 12 + 16:  # nonce + tag
            raise ValueError("Invalid ciphertext length")
            
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(self.security_context['aes_key'])
        return aesgcm.decrypt(nonce, ciphertext, None)

    def send_message(self, message):
        """Encrypt and send message to server"""
        if not self.connected:
            raise RuntimeError("Not connected to server")
            
        try:
            plaintext = message.encode('utf-8')
            encrypted = self.encrypt_message(plaintext)
            self.secure_sock.sendall(encrypted)
            return True
        except Exception as e:
            self.log(f"Send error: {str(e)}")
            return False

    def receive_message(self):
        """Receive and decrypt message from server"""
        try:
            data = self.secure_sock.recv(4096)
            if not data:
                return None
                
            plaintext = self.decrypt_message(data)
            return plaintext.decode('utf-8')
        except socket.timeout:
            return None
        except Exception as e:
            self.log(f"Receive error: {str(e)}")
            return None

if not IS_MOBILE:
    class DesktopChat:
        def __init__(self, root):
            self.root = root
            self.root.protocol("WM_DELETE_WINDOW", self.on_close)
            self.connection_status = False
            self.setup_ui()
            
            # Start connection in background thread
            self.thread = threading.Thread(target=self.initialize_connection, daemon=True)
            self.thread.start()

        def setup_ui(self):
            self.root.geometry("900x700")
            self.root.title("Secure Chat Client")
            self.root.configure(bg="#f0f0f0")
            
            # Custom fonts
            title_font = font.Font(family="Helvetica", size=16, weight="bold")
            status_font = font.Font(family="Helvetica", size=10)
            
            # Status bar
            self.status_var = tk.StringVar(value="Connecting to server...")
            status_bar = tk.Label(
                self.root, textvariable=self.status_var, 
                anchor=tk.W, bg="#e0e0e0", font=status_font
            )
            status_bar.pack(side=tk.BOTTOM, fill=tk.X)
            
            # Chat display
            chat_frame = tk.Frame(self.root, bg="#f0f0f0")
            chat_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
            
            self.chat_display = scrolledtext.ScrolledText(
                chat_frame, state='disabled', wrap=tk.WORD, 
                bg="white", font=("Consolas", 10)
            )
            self.chat_display.pack(expand=True, fill=tk.BOTH)
            self.chat_display.tag_config("error", foreground="red")
            
            # Input area
            input_frame = tk.Frame(self.root, bg="#f0f0f0")
            input_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
            
            self.msg_entry = tk.Entry(
                input_frame, width=70, font=("Arial", 12)
            )
            self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
            self.msg_entry.bind("<Return>", lambda e: self.send_message())
            
            send_btn = tk.Button(
                input_frame, text="Send", command=self.send_message,
                bg="#4CAF50", fg="white", font=("Arial", 10, "bold")
            )
            send_btn.pack(side=tk.RIGHT)

        def initialize_connection(self):
            try:
                self.core = SecureChatCore(ui_callback=self.update_chat)
                self.connection_status = True
                self.status_var.set("Connected to server")
                threading.Thread(target=self.receive_messages, daemon=True).start()
            except RuntimeError as e:
                self.status_var.set(f"Connection failed: {str(e)}")
                messagebox.showerror("Connection Error", str(e))
                self.root.after(2000, self.root.destroy)

        def send_message(self):
            if not hasattr(self, 'core') or not self.connection_status:
                messagebox.showerror("Error", "Not connected to server")
                return
                
            message = self.msg_entry.get()
            if message:
                try:
                    if self.core.send_message(message):
                        self.update_chat(f"You: {message}")
                        self.msg_entry.delete(0, tk.END)
                except Exception as e:
                    self.update_chat(f"Error: {str(e)}", error=True)

        def receive_messages(self):
            while self.connection_status:
                try:
                    message = self.core.receive_message()
                    if message:
                        self.update_chat(f"Server: {message}")
                except Exception as e:
                    self.update_chat(f"Receive error: {str(e)}", error=True)
                    self.connection_status = False
                time.sleep(0.1)

        def update_chat(self, message, error=False):
            self.chat_display.config(state='normal')
            if error:
                self.chat_display.insert(tk.END, message + '\n', "error")
            else:
                self.chat_display.insert(tk.END, message + '\n')
            self.chat_display.config(state='disabled')
            self.chat_display.see(tk.END)

        def on_close(self):
            if hasattr(self, 'core') and hasattr(self.core, 'secure_sock'):
                try:
                    self.core.secure_sock.close()
                except:
                    pass
            self.root.destroy()

if __name__ == '__main__':
    if IS_MOBILE:
        # Mobile implementation would go here
        pass
    else:
        root = tk.Tk()
        app = DesktopChat(root)
        root.mainloop()
