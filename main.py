import sys
import os
import hashlib
import subprocess
import json
import websocket
import threading
from datetime import datetime
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit, QMessageBox, QTableWidget, QTableWidgetItem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class GymApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gym Management System")
        self.setGeometry(100, 100, 800, 600)
        self.members = []
        self.device_fingerprint = self.get_device_fingerprint()
        self.config_file = "config.enc"
        self.activation_file = "activation.enc"
        self.key = b'0123456789abcdef0123456789abcdef'  # مفتاح 32 بايت
        self.gym_id = None
        self.subscription_type = None
        self.expiry_date = None
        if not self.verify_device():
            QMessageBox.critical(self, "Security Error", "Device verification failed!")
            sys.exit(1)
        self.check_activation()
        self.init_ui()
        self.start_websocket()

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

    def verify_device(self):
        if not os.path.exists(self.config_file):
            QMessageBox.critical(self, "Error", "Configuration file missing!")
            return False
        try:
            with open(self.config_file, 'rb') as f:
                nonce, ciphertext = f.read(12), f.read()
            aesgcm = AESGCM(self.key)
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            config = json.loads(decrypted.decode())
            return config.get("fingerprint") == self.device_fingerprint
        except Exception as e:
            print(f"Verification error: {e}")
            return False

    def check_activation(self):
        if not os.path.exists(self.activation_file):
            self.prompt_activation_code()
            return
        try:
            with open(self.activation_file, 'rb') as f:
                nonce, ciphertext = f.read(12), f.read()
            aesgcm = AESGCM(self.key)
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            activation = json.loads(decrypted.decode())
            self.gym_id = activation.get("gym_id")
            self.subscription_type = activation.get("subscription_type")
            expiry = datetime.fromisoformat(activation.get("expiry_date"))
            if datetime.now() > expiry:
                QMessageBox.critical(self, "Error", "Activation code expired!")
                self.prompt_activation_code()
            else:
                QMessageBox.information(self, "Success", f"Active Subscription: {self.subscription_type} until {expiry}")
        except Exception as e:
            print(f"Activation error: {e}")
            self.prompt_activation_code()

    def prompt_activation_code(self):
        from PyQt5.QtWidgets import QInputDialog  # أضف هذا في بداية الملف إذا مش موجود
        code, ok = QInputDialog.getText(self, "Activation", "Enter activation code:")
        if ok and code:
            self.verify_code_online(code)
        else:
            sys.exit(1)

    def verify_code_online(self, code):
        # هنا هنجرب نتصل بالموقع للتحقق من الكود (في النسخة الكاملة)
        # دلوقتي بنفترض إن الكود صح
        # هيتم استبداله بطلب HTTP للموقع
        import requests
        try:
            response = requests.post("https://yactive.up.railway.app/verify_code", json={"code": code, "gym_id": self.gym_id})
            if response.status_code == 200:
                data = response.json()
                self.save_activation(data["code"], data["subscription_type"], data["expiry_date"])
                QMessageBox.information(self, "Success", "Activation successful!")
            else:
                QMessageBox.critical(self, "Error", "Invalid activation code!")
                self.prompt_activation_code()
        except Exception as e:
            print(f"Online verification error: {e}")
            self.prompt_activation_code()

    def save_activation(self, code, subscription_type, expiry_date):
        try:
            activation = {
                "gym_id": self.gym_id,
                "code": code,
                "subscription_type": subscription_type,
                "expiry_date": expiry_date
            }
            aesgcm = AESGCM(self.key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, json.dumps(activation).encode(), None)
            with open(self.activation_file, 'wb') as f:
                f.write(nonce + ciphertext)
        except Exception as e:
            print(f"Error saving activation: {e}")

    def start_websocket(self):
        def on_message(ws, message):
            try:
                data = json.loads(message)
                if data.get("gym_id") == self.gym_id:
                    self.save_activation(data["code"], data["subscription_type"], data["expiry_date"])
                    QMessageBox.information(self, "Success", "New activation code received!")
            except Exception as e:
                print(f"WebSocket error: {e}")

        def on_error(ws, error):
            print(f"WebSocket error: {error}")

        def on_close(ws, close_status_code, close_msg):
            print("WebSocket closed, reconnecting...")
            threading.Timer(5, self.start_websocket).start()

        ws = websocket.WebSocketApp(
            "wss://yactive.up.railway.app/ws",
            on_message=on_message,
            on_error=on_error,
            on_close=on_close
        )
        threading.Thread(target=ws.run_forever, daemon=True).start()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Enter member name")
        layout.addWidget(self.name_input)
        add_button = QPushButton("Add Member")
        add_button.clicked.connect(self.add_member)
        layout.addWidget(add_button)
        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["ID", "Name"])
        layout.addWidget(self.table)
        show_button = QPushButton("Show Members")
        show_button.clicked.connect(self.show_members)
        layout.addWidget(show_button)

    def add_member(self):
        name = self.name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "Input Error", "Please enter a name!")
            return
        member_id = len(self.members) + 1
        self.members.append({"id": member_id, "name": name})
        QMessageBox.information(self, "Success", f"Member {name} added!")
        self.name_input.clear()

    def show_members(self):
        self.table.setRowCount(len(self.members))
        for row, member in enumerate(self.members):
            self.table.setItem(row, 0, QTableWidgetItem(str(member["id"])))
            self.table.setItem(row, 1, QTableWidgetItem(member["name"]))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GymApp()
    window.show()
    sys.exit(app.exec_())
