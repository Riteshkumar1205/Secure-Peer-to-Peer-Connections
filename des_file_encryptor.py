import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QMessageBox
)
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def validate_key(key_hex: str) -> bytes:
    """Validate and convert a 16-hex-digit string to bytes for DES."""
    if len(key_hex) != 16 or any(c not in "0123456789abcdefABCDEF" for c in key_hex):
        raise ValueError("Key must be exactly 16 hex digits (0-9, A-F).")
    return bytes.fromhex(key_hex)

def encrypt_des(data: bytes, key: bytes) -> bytes:
    """Encrypt data using DES in CBC mode with a random IV."""
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, DES.block_size))
    return cipher.iv + ct_bytes  # Prepend IV for decryption

def decrypt_des(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt data using DES in CBC mode (IV is first 8 bytes)."""
    iv = ciphertext[:DES.block_size]
    ct = ciphertext[DES.block_size:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), DES.block_size)
    return pt

class DesGuiApp(QWidget):
    def __init__(self):
        super().__init__()
        self.file_path = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("DES File Encryptor/Decryptor")
        layout = QVBoxLayout()

        self.instruction_label = QLabel("Step 1: Select a file to encrypt or decrypt.")
        layout.addWidget(self.instruction_label)

        self.file_label = QLabel("No file selected")
        layout.addWidget(self.file_label)

        self.select_file_btn = QPushButton("Select File")
        self.select_file_btn.clicked.connect(self.select_file)
        layout.addWidget(self.select_file_btn)

        self.key_label = QLabel("Step 2: Enter 16-hex-digit key (e.g. AABB09182736CCDD):")
        layout.addWidget(self.key_label)

        self.key_input = QLineEdit()
        self.key_input.setMaxLength(16)
        self.key_input.setPlaceholderText("Enter 16 hex digits key")
        layout.addWidget(self.key_input)

        self.encrypt_btn = QPushButton("Encrypt")
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        self.encrypt_btn.setEnabled(False)
        layout.addWidget(self.encrypt_btn)

        self.decrypt_btn = QPushButton("Decrypt")
        self.decrypt_btn.clicked.connect(self.decrypt_file)
        self.decrypt_btn.setEnabled(False)
        layout.addWidget(self.decrypt_btn)

        self.status_label = QLabel("")
        layout.addWidget(self.status_label)

        self.key_input.textChanged.connect(self.validate_inputs)

        self.setLayout(layout)

    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path = file_path
            self.file_label.setText(f"Selected file: {os.path.basename(file_path)}")
            self.validate_inputs()

    def validate_inputs(self):
        key = self.key_input.text()
        if self.file_path and len(key) == 16 and all(c in '0123456789ABCDEFabcdef' for c in key):
            self.encrypt_btn.setEnabled(True)
            self.decrypt_btn.setEnabled(True)
            self.status_label.setText("")
        else:
            self.encrypt_btn.setEnabled(False)
            self.decrypt_btn.setEnabled(False)
            if not self.file_path:
                self.status_label.setText("Please select a file.")
            elif len(key) != 16 or not all(c in '0123456789ABCDEFabcdef' for c in key):
                self.status_label.setText("Key must be exactly 16 hex digits.")

    def encrypt_file(self):
        try:
            output_file = self.process_file(encrypt=True)
            self.status_label.setText(f"Encryption successful! Output saved as: {output_file}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")

    def decrypt_file(self):
        try:
            output_file = self.process_file(encrypt=False)
            self.status_label.setText(f"Decryption successful! Output saved as: {output_file}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")

    def process_file(self, encrypt=True):
        with open(self.file_path, "rb") as f:
            data = f.read()
        key_hex = self.key_input.text().upper()
        key_bytes = validate_key(key_hex)
        if encrypt:
            processed_data = encrypt_des(data, key_bytes)
            suffix = "_encrypted"
        else:
            processed_data = decrypt_des(data, key_bytes)
            suffix = "_decrypted"
        base, ext = os.path.splitext(self.file_path)
        output_file = base + suffix + ext
        with open(output_file, "wb") as f:
            f.write(processed_data)
        return os.path.basename(output_file)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DesGuiApp()
    window.show()
    sys.exit(app.exec_())
