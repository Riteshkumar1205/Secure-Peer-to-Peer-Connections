import sys
import os
import secrets
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QMessageBox, QGroupBox,
    QHBoxLayout, QCheckBox, QTextEdit
)
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtCore import Qt
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def validate_key(key_hex: str) -> bytes:
    """Validate and convert a 16-hex-digit string to bytes for DES."""
    if len(key_hex) != 16 or any(c not in "0123456789abcdefABCDEF" for c in key_hex):
        raise ValueError("Key must be exactly 16 hex digits (0-9, A-F).")
    return bytes.fromhex(key_hex)

def generate_random_key() -> bytes:
    """Generate a cryptographically secure random DES key"""
    return secrets.token_bytes(8)  # 64-bit key for DES

def encrypt_des(data: bytes, key: bytes) -> bytes:
    """Encrypt data using DES in CBC mode with a random IV."""
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, DES.block_size))
    return cipher.iv + ct_bytes  # Prepend IV for decryption

def decrypt_des(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt data using DES in CBC mode (IV is first 8 bytes)."""
    if len(ciphertext) < DES.block_size:
        raise ValueError("Ciphertext too short to contain IV")
    
    iv = ciphertext[:DES.block_size]
    ct = ciphertext[DES.block_size:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    
    try:
        pt = unpad(cipher.decrypt(ct), DES.block_size)
    except ValueError as e:
        raise ValueError("Decryption failed: Invalid padding") from e
    
    return pt

class DesGuiApp(QWidget):
    def __init__(self):
        super().__init__()
        self.file_path = None
        self.init_ui()
        self.setStyleSheet("""
            QWidget {
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QGroupBox {
                border: 1px solid #3498db;
                border-radius: 5px;
                margin-top: 1ex;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #2980b9;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
            }
            QTextEdit {
                border: 1px solid #bdc3c7;
                border-radius: 4px;
            }
        """)

    def init_ui(self):
        self.setWindowTitle("DES File Encryptor/Decryptor")
        self.setMinimumSize(600, 500)
        
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        
        # File Selection Group
        file_group = QGroupBox("File Operations")
        file_layout = QVBoxLayout()
        
        self.file_label = QLabel("No file selected")
        self.file_label.setWordWrap(True)
        file_layout.addWidget(self.file_label)
        
        btn_layout = QHBoxLayout()
        self.select_file_btn = QPushButton("Select File")
        self.select_file_btn.clicked.connect(self.select_file)
        btn_layout.addWidget(self.select_file_btn)
        
        self.clear_file_btn = QPushButton("Clear Selection")
        self.clear_file_btn.clicked.connect(self.clear_file)
        self.clear_file_btn.setEnabled(False)
        btn_layout.addWidget(self.clear_file_btn)
        
        file_layout.addLayout(btn_layout)
        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)
        
        # Key Management Group
        key_group = QGroupBox("Encryption Key")
        key_layout = QVBoxLayout()
        
        key_input_layout = QHBoxLayout()
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter 16 hex digits (0-9, A-F)")
        self.key_input.setMaxLength(16)
        self.key_input.textChanged.connect(self.validate_inputs)
        key_input_layout.addWidget(self.key_input)
        
        self.toggle_key_visibility = QCheckBox("Show")
        self.toggle_key_visibility.stateChanged.connect(self.toggle_key_visibility_changed)
        key_input_layout.addWidget(self.toggle_key_visibility)
        
        key_layout.addLayout(key_input_layout)
        
        key_btn_layout = QHBoxLayout()
        self.generate_key_btn = QPushButton("Generate Random Key")
        self.generate_key_btn.clicked.connect(self.generate_random_key)
        key_btn_layout.addWidget(self.generate_key_btn)
        
        self.copy_key_btn = QPushButton("Copy Key")
        self.copy_key_btn.clicked.connect(self.copy_key_to_clipboard)
        self.copy_key_btn.setEnabled(False)
        key_btn_layout.addWidget(self.copy_key_btn)
        
        key_layout.addLayout(key_btn_layout)
        
        key_info = QLabel(
            "DES uses a 64-bit key (16 hex characters). "
            "For security, generate a random key for each operation."
        )
        key_info.setWordWrap(True)
        key_info.setStyleSheet("color: #7f8c8d; font-style: italic;")
        key_layout.addWidget(key_info)
        
        key_group.setLayout(key_layout)
        main_layout.addWidget(key_group)
        
        # Action Buttons
        action_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("Encrypt File")
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        self.encrypt_btn.setEnabled(False)
        self.encrypt_btn.setStyleSheet("background-color: #2ecc71;")
        action_layout.addWidget(self.encrypt_btn)
        
        self.decrypt_btn = QPushButton("Decrypt File")
        self.decrypt_btn.clicked.connect(self.decrypt_file)
        self.decrypt_btn.setEnabled(False)
        self.decrypt_btn.setStyleSheet("background-color: #e74c3c;")
        action_layout.addWidget(self.decrypt_btn)
        
        main_layout.addLayout(action_layout)
        
        # Status Display
        self.status_display = QTextEdit()
        self.status_display.setReadOnly(True)
        self.status_display.setPlaceholderText("Operation status will appear here...")
        main_layout.addWidget(QLabel("Status:"))
        main_layout.addWidget(self.status_display)
        
        self.setLayout(main_layout)

    def toggle_key_visibility_changed(self, state):
        if state == Qt.Checked:
            self.key_input.setEchoMode(QLineEdit.Normal)
        else:
            self.key_input.setEchoMode(QLineEdit.Password)

    def generate_random_key(self):
        """Generate and display a random DES key"""
        key_bytes = generate_random_key()
        key_hex = key_bytes.hex().upper()
        self.key_input.setText(key_hex)
        self.log_status(f"Generated new random key: {key_hex}", success=True)
        self.copy_key_btn.setEnabled(True)

    def copy_key_to_clipboard(self):
        """Copy current key to clipboard"""
        key = self.key_input.text()
        if key:
            clipboard = QApplication.clipboard()
            clipboard.setText(key)
            self.log_status("Key copied to clipboard", success=True)

    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path = file_path
            filename = os.path.basename(file_path)
            self.file_label.setText(f"Selected file: {filename}\nSize: {os.path.getsize(file_path):,} bytes")
            self.clear_file_btn.setEnabled(True)
            self.validate_inputs()

    def clear_file(self):
        self.file_path = None
        self.file_label.setText("No file selected")
        self.clear_file_btn.setEnabled(False)
        self.validate_inputs()

    def validate_inputs(self):
        key = self.key_input.text()
        key_valid = len(key) == 16 and all(c in '0123456789ABCDEFabcdef' for c in key)
        file_selected = self.file_path is not None
        
        self.encrypt_btn.setEnabled(key_valid and file_selected)
        self.decrypt_btn.setEnabled(key_valid and file_selected)
        self.copy_key_btn.setEnabled(bool(key))
        
        # Update status
        if not file_selected:
            self.log_status("Please select a file", error=True)
        elif not key_valid:
            if key:
                self.log_status("Key must be exactly 16 hex digits (0-9, A-F)", error=True)
            else:
                self.log_status("Please enter or generate a key", error=True)
        else:
            self.log_status("Ready for encryption/decryption", success=True)

    def encrypt_file(self):
        try:
            output_file = self.process_file(encrypt=True)
            self.log_status(
                f"Encryption successful!\nOutput saved as: {output_file}", 
                success=True
            )
        except Exception as e:
            self.log_status(f"Encryption failed: {str(e)}", error=True)
            QMessageBox.critical(self, "Encryption Error", f"Encryption failed:\n{str(e)}")

    def decrypt_file(self):
        try:
            output_file = self.process_file(encrypt=False)
            self.log_status(
                f"Decryption successful!\nOutput saved as: {output_file}", 
                success=True
            )
        except Exception as e:
            self.log_status(f"Decryption failed: {str(e)}", error=True)
            QMessageBox.critical(self, "Decryption Error", f"Decryption failed:\n{str(e)}")

    def process_file(self, encrypt=True):
        # Read file
        with open(self.file_path, "rb") as f:
            data = f.read()
        
        # Validate key
        key_hex = self.key_input.text().upper()
        key_bytes = validate_key(key_hex)
        
        # Process data
        if encrypt:
            processed_data = encrypt_des(data, key_bytes)
            suffix = "_encrypted"
            action = "Encrypting"
        else:
            processed_data = decrypt_des(data, key_bytes)
            suffix = "_decrypted"
            action = "Decrypting"
        
        # Save output
        base, ext = os.path.splitext(self.file_path)
        output_file = base + suffix + ext
        
        # Handle file overwrite
        counter = 1
        while os.path.exists(output_file):
            output_file = f"{base}{suffix}_{counter}{ext}"
            counter += 1
        
        with open(output_file, "wb") as f:
            f.write(processed_data)
        
        return os.path.basename(output_file)

    def log_status(self, message, success=False, error=False):
        """Append message to status display with color coding"""
        if success:
            formatted = f"<span style='color: #27ae60;'>{message}</span>"
        elif error:
            formatted = f"<span style='color: #e74c3c;'>{message}</span>"
        else:
            formatted = message
        
        self.status_display.append(formatted)
        self.status_display.verticalScrollBar().setValue(
            self.status_display.verticalScrollBar().maximum()
        )

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(240, 240, 240))
    app.setPalette(palette)
    
    window = DesGuiApp()
    window.show()
    sys.exit(app.exec_())
