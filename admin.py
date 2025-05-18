import sys
import os
import subprocess
import hashlib
import json
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit, QMessageBox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import bcrypt

class AdminApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Admin Panel - Gym Management")
        self.setGeometry(100, 100, 400, 300)
        self.key = b'0123456789abcdef0123456789abcdef'  # يجب تخزينه بأمان
        self.config_file = "config.enc"
        self.admin_password_hash = bcrypt.hashpw(b"admin123", bcrypt.gensalt())  # كلمة مرور افتراضية
        self.init_ui()

    def get_device_fingerprint(self):
        try:
            cpu_info = subprocess.check_output("lscpu | grep 'Model name'", shell=True).decode().strip()
            board_info = subprocess.check_output("sudo dmidecode -s baseboard-serial-number", shell=True).decode().strip()
            bios_info = subprocess.check_output("sudo dmidecode -s bios-version", shell=True).decode().strip()
            combined = f"{cpu_info}{board_info}{bios_info}"
            return hashlib.sha256(combined.encode()).hexdigest()
        except Exception as e:
            print(f"Error getting fingerprint: {e}")
            return None

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # إدخال كلمة مرور الأدمن
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter admin password")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        login_button = QPushButton("Login")
        login_button.clicked.connect(self.verify_admin)
        layout.addWidget(login_button)

        # زر عرض معلومات الجهاز
        self.device_button = QPushButton("Show Device Info")
        self.device_button.clicked.connect(self.show_device_info)
        self.device_button.setEnabled(False)
        layout.addWidget(self.device_button)

        # زر إنشاء ملف تكوين
        self.config_button = QPushButton("Generate Config File")
        self.config_button.clicked.connect(self.generate_config)
        self.config_button.setEnabled(False)
        layout.addWidget(self.config_button)

    def verify_admin(self):
        password = self.password_input.text().encode()
        if bcrypt.checkpw(password, self.admin_password_hash):
            self.device_button.setEnabled(True)
            self.config_button.setEnabled(True)
            QMessageBox.information(self, "Success", "Admin verified!")
        else:
            QMessageBox.critical(self, "Error", "Invalid password!")
            self.password_input.clear()

    def show_device_info(self):
        fingerprint = self.get_device_fingerprint()
        if fingerprint:
            QMessageBox.information(self, "Device Info", f"Device Fingerprint: {fingerprint}")
        else:
            QMessageBox.critical(self, "Error", "Failed to retrieve device info!")

    def generate_config(self):
        fingerprint = self.get_device_fingerprint()
        if not fingerprint:
            QMessageBox.critical(self, "Error", "Cannot generate config: No device fingerprint!")
            return
        try:
            # إنشاء ملف تكوين مشفر
            config = {"fingerprint": fingerprint}
            aesgcm = AESGCM(self.key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, json.dumps(config).encode(), None)
            with open(self.config_file, 'wb') as f:
                f.write(nonce + ciphertext)
            QMessageBox.information(self, "Success", f"Config file generated: {self.config_file}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate config: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AdminApp()
    window.show()
    sys.exit(app.exec_())
