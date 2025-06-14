# secure_chat_universal.py
import sys
import os
import socket
import ssl
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

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
    from tkinter import scrolledtext, messagebox

# ======== SECURITY CONFIG ========
HOST = 'your.server.com'
PORT = 1234
CERT_FILE = './server.crt'

# ======== CRYPTO CONFIG ========
AES_KEY_SIZE = 256 // 8
HMAC_KEY_SIZE = 256 // 8
NONCE_SIZE = 12

class SecureChatCore:
    def __init__(self):
        self.security_context = {
            'cipher': None,
            'hmac_key': None,
            'sequence': 0
        }
        self.setup_connection()

    def setup_connection(self):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations(CERT_FILE)
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_sock = context.wrap_socket(
            self.sock, server_hostname=HOST
        )
        self.secure_sock.connect((HOST, PORT))
        
        # Key exchange
        shared_secret = os.urandom(32)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE + HMAC_KEY_SIZE,
            salt=None,
            info=b'secure_chat_session',
            backend=default_backend()
        )
        keys = hkdf.derive(shared_secret)
        aes_key = keys[:AES_KEY_SIZE]
        hmac_key = keys[AES_KEY_SIZE:]
        
        self.security_context.update({
            'cipher': Cipher(
                algorithms.AES(aes_key),
                modes.GCM(os.urandom(NONCE_SIZE)),
                backend=default_backend()
            ),
            'hmac_key': hmac_key
        })

    def encrypt_message(self, plaintext):
        encryptor = self.security_context['cipher'].encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return encryptor.tag, ciphertext

    def decrypt_message(self, ciphertext, tag):
        decryptor = self.security_context['cipher'].decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize_with_tag(tag)

if IS_MOBILE:
    # Android Kivy UI
    class ChatApp(App):
        def build(self):
            self.core = SecureChatCore()
            self.layout = BoxLayout(orientation='vertical')
            
            self.chat_log = ScrollView()
            self.chat_text = Label(
                text='', size_hint_y=None,
                text_size=(Window.width, None),
                halign='left', valign='top'
            )
            self.chat_log.add_widget(self.chat_text)
            
            self.input_layout = BoxLayout(size_hint_y=0.15)
            self.msg_input = TextInput()
            self.send_btn = Button(text="Send", on_press=self.send_message)
            
            self.input_layout.add_widget(self.msg_input)
            self.input_layout.add_widget(self.send_btn)
            
            self.layout.add_widget(self.chat_log)
            self.layout.add_widget(self.input_layout)
            
            threading.Thread(target=self.receive_messages, daemon=True).start()
            return self.layout

        def send_message(self, instance):
            message = self.msg_input.text
            if message:
                try:
                    tag, ciphertext = self.core.encrypt_message(message.encode())
                    h = hmac.HMAC(
                        self.core.security_context['hmac_key'],
                        hashes.SHA256(),
                        backend=default_backend()
                    )
                    h.update(ciphertext)
                    mac = h.finalize()
                    self.core.secure_sock.sendall(b''.join([tag, mac, ciphertext]))
                    self.msg_input.text = ''
                except Exception as e:
                    self.show_error(str(e))

        def receive_messages(self):
            while True:
                try:
                    data = self.core.secure_sock.recv(4096)
                    if not data: break
                    
                    tag = data[:16]
                    received_mac = data[16:48]
                    ciphertext = data[48:]
                    
                    h = hmac.HMAC(
                        self.core.security_context['hmac_key'],
                        hashes.SHA256(),
                        backend=default_backend()
                    )
                    h.update(ciphertext)
                    h.verify(received_mac)
                    
                    plaintext = self.core.decrypt_message(ciphertext, tag)
                    self.update_chat(plaintext.decode())
                except Exception as e:
                    self.show_error(str(e))
                    break

        def update_chat(self, message):
            self.chat_text.text += '\n' + message
            self.chat_text.height = max(
                self.chat_text.texture_size[1], Window.height
            )

        def show_error(self, message):
            self.chat_text.text += '\n[ERROR] ' + message

else:
    # Desktop Tkinter UI
    class DesktopChat:
        def __init__(self, root):
            self.root = root
            self.core = SecureChatCore()
            self.setup_ui()
            threading.Thread(target=self.receive_messages, daemon=True).start()

        def setup_ui(self):
            self.root.geometry("800x600")
            self.root.title("Secure Chat")
            
            # Chat display
            self.chat_display = scrolledtext.ScrolledText(
                state='disabled', wrap=tk.WORD
            )
            self.chat_display.pack(expand=True, fill='both')
            
            # Input area
            input_frame = tk.Frame(self.root)
            self.msg_entry = tk.Entry(input_frame, width=70)
            self.msg_entry.pack(side=tk.LEFT, padx=5)
            
            send_btn = tk.Button(
                input_frame, text="Send", command=self.send_message
            )
            send_btn.pack(side=tk.RIGHT)
            input_frame.pack(pady=10)

        def send_message(self):
            message = self.msg_entry.get()
            if message:
                try:
                    tag, ciphertext = self.core.encrypt_message(message.encode())
                    h = hmac.HMAC(
                        self.core.security_context['hmac_key'],
                        hashes.SHA256(),
                        backend=default_backend()
                    )
                    h.update(ciphertext)
                    mac = h.finalize()
                    self.core.secure_sock.sendall(b''.join([tag, mac, ciphertext]))
                    self.msg_entry.delete(0, tk.END)
                except Exception as e:
                    self.show_error(str(e))

        def receive_messages(self):
            while True:
                try:
                    data = self.core.secure_sock.recv(4096)
                    if not data: break
                    
                    tag = data[:16]
                    received_mac = data[16:48]
                    ciphertext = data[48:]
                    
                    h = hmac.HMAC(
                        self.core.security_context['hmac_key'],
                        hashes.SHA256(),
                        backend=default_backend()
                    )
                    h.update(ciphertext)
                    h.verify(received_mac)
                    
                    plaintext = self.core.decrypt_message(ciphertext, tag)
                    self.update_chat(plaintext.decode())
                except Exception as e:
                    self.show_error(str(e))
                    break

        def update_chat(self, message):
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, message + '\n')
            self.chat_display.config(state='disabled')
            self.chat_display.see(tk.END)

        def show_error(self, message):
            messagebox.showerror("Error", message)

if __name__ == '__main__':
    if IS_MOBILE:
        ChatApp().run()
    else:
        root = tk.Tk()
        app = DesktopChat(root)
        root.mainloop()
