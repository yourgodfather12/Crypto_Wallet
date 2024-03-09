import sys
import os
import hashlib
import ecdsa
import requests
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QTextEdit, QVBoxLayout, QPushButton,
    QComboBox, QMainWindow, QHBoxLayout, QMessageBox, QLineEdit, QProgressBar
)
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtCore import Qt, QObject, pyqtSignal, QThread
import base58

class FetchDataThread(QThread):
    data_fetched = pyqtSignal(dict)

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        try:
            response = requests.get(self.url)
            if response.status_code == 200:
                data = response.json()
                self.data_fetched.emit(data)
            else:
                self.data_fetched.emit({"error": f"Error {response.status_code}: {response.reason}"})
        except requests.RequestException as e:
            self.data_fetched.emit({"error": f"Error fetching data: {e}"})

class CryptoWallet:
    def __init__(self):
        self.currencies = {
            "Bitcoin": {"explorer": "blockchain.com",
                        "price_api": "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"},
            "Ethereum": {"explorer": "etherscan.io",
                         "price_api": "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"},
            # Add more cryptocurrencies here
        }

        self.selected_currency = "Bitcoin"
        self.addresses_file = "addresses.txt"
        self.addresses = {}
        self.private_key = None
        self.public_key = None
        self.address = None
        self.balance = None
        self.price = None
        self.balance_api = "https://api.blockchair.com/{currency}/addresses/{address}/balance"

    def generate_wallet(self):
        self.private_key = self.generate_private_key()
        uncompressed_public_key, _ = self.generate_public_key(self.private_key)  # Ignore the compressed public key
        self.address = self.generate_address(uncompressed_public_key, self.currencies[self.selected_currency]["explorer"])
        self.save_address()

    def save_address(self):
        with open(self.addresses_file, "a") as f:
            f.write(f"{self.selected_currency},{self.address}\n")

    def load_addresses(self):
        if not os.path.exists(self.addresses_file):
            return
        with open(self.addresses_file, "r") as f:
            for line in f:
                currency, address = line.strip().split(",")
                self.addresses[currency] = address

    def get_address(self):
        return self.addresses.get(self.selected_currency, "No address found")

    def fetch_balance(self):
        address = self.get_address()
        if address:
            url = f"https://api.blockchair.com/{self.selected_currency.lower()}/addresses/{address}/balance"
            thread = FetchDataThread(url)
            thread.data_fetched.connect(self.update_balance)
            thread.start()
        else:
            self.balance = None

    def update_balance(self, data):
        if "error" in data:
            print(data["error"])
            self.balance = None
        else:
            balance_satoshis = int(data)
            self.balance = balance_satoshis / 100000000

    def display_balance(self):
        if self.balance is not None:
            if self.balance == 0:
                return "Your current balance is 0. No funds available."
            elif self.price is not None:
                crypto_balance = f"{self.balance:,.8f} {self.selected_currency}"
                usd_balance = f"${self.balance * self.price:,.2f} USD"
                return f"Your current balance is {crypto_balance} ({usd_balance})."
            else:
                return f"Your current balance is {self.balance:,.8f} {self.selected_currency}. Price data not available."
        else:
            return "Fetching balance..."

    def fetch_price(self):
        url = self.currencies[self.selected_currency]["price_api"]
        thread = FetchDataThread(url)
        thread.data_fetched.connect(self.update_price)
        thread.start()

    def update_price(self, data):
        if "error" in data:
            print(data["error"])
            self.price = None
        else:
            self.price = data[self.selected_currency.lower()]["usd"]

    @staticmethod
    def generate_private_key():
        key_bytes = os.urandom(32)
        key_int = int.from_bytes(key_bytes, byteorder='big')
        return key_int

    @staticmethod
    def generate_public_key(private_key):
        sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, byteorder='big'), curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        uncompressed_public_key = b'\x04' + vk.to_string()
        compressed_public_key = vk.to_string("compressed")
        return uncompressed_public_key, compressed_public_key

    def generate_address(self, public_key, explorer):
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashlib.sha256(public_key).digest())
        hash160 = ripemd160.digest()
        address = hash160_to_p2pkh(hash160)  # Corrected call to helper function
        return address

    def send_transaction(self, recipient_address, amount):
        # Implement transaction sending logic here
        pass

def hash160_to_p2pkh(hash160):
    # Step 1: Prepend version byte (0x00 for mainnet, 0x6f for testnet)
    version_byte = b'\x00'  # Assuming mainnet address

    # Step 2: Add version byte to hash160
    extended_hash160 = version_byte + hash160

    # Step 3: Calculate checksum (double SHA256 hash of extended hash160)
    checksum = hashlib.sha256(hashlib.sha256(extended_hash160).digest()).digest()[:4]

    # Step 4: Append checksum to extended hash160
    extended_hash160_checksum = extended_hash160 + checksum

    # Step 5: Base58 encode the extended hash160 with checksum
    bitcoin_address = base58.b58encode(extended_hash160_checksum)

    return bitcoin_address.decode('utf-8')  # Convert bytes to string

class CryptoWalletGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.wallet = CryptoWallet()
        self.wallet.load_addresses()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Crypto Wallet")
        self.setWindowIcon(QIcon("icon.png"))

        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        layout = QVBoxLayout(main_widget)

        # Dark theme stylesheet
        dark_theme_stylesheet = """
            QMainWindow {
                background-color: #222;
            }
            QLabel {
                color: #fff;
            }
            QTextEdit, QLineEdit {
                background-color: #333;
                color: #fff;
                border: 1px solid #555;
                padding: 5px;
            }
            QPushButton {
                background-color: #007bff;
                color: #fff;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QComboBox {
                background-color: #333;
                color: #fff;
                border: 1px solid #555;
                padding: 5px;
                selection-background-color: #007bff;
            }
        """
        self.setStyleSheet(dark_theme_stylesheet)

        header_label = QLabel("Manage Your Crypto Wallet")
        header_label.setAlignment(Qt.AlignCenter)
        header_font = QFont("Poppins", 16, QFont.Bold)  # Using Poppins font
        header_label.setFont(header_font)
        layout.addWidget(header_label)

        currency_layout = QHBoxLayout()
        self.currency_label = QLabel("Select Currency:")
        self.currency_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.currency_combo_box = QComboBox()
        for currency in self.wallet.currencies:
            self.currency_combo_box.addItem(currency)
        self.currency_combo_box.currentIndexChanged.connect(self.change_currency)

        currency_layout.addWidget(self.currency_label)
        currency_layout.addWidget(self.currency_combo_box)
        layout.addLayout(currency_layout)

        self.address_label = QLabel("Wallet Address:")
        self.address_text = QTextEdit()
        self.address_text.setReadOnly(True)
        self.address_text.setMaximumHeight(50)

        self.balance_label = QLabel("Balance:")
        self.balance_text = QLabel()

        self.price_label = QLabel("Current Price (USD):")
        self.price_text = QLabel()

        info_layout = QVBoxLayout()
        info_layout.addWidget(self.address_label)
        info_layout.addWidget(self.address_text)
        info_layout.addWidget(self.balance_label)
        info_layout.addWidget(self.balance_text)
        info_layout.addWidget(self.price_label)
        info_layout.addWidget(self.price_text)

        layout.addLayout(info_layout)

        send_layout = QHBoxLayout()
        self.recipient_label = QLabel("Recipient Address:")
        self.recipient_text = QLineEdit()
        send_layout.addWidget(self.recipient_label)
        send_layout.addWidget(self.recipient_text)
        layout.addLayout(send_layout)

        self.amount_label = QLabel("Amount:")
        self.amount_text = QLineEdit()
        layout.addWidget(self.amount_label)
        layout.addWidget(self.amount_text)

        button_layout = QHBoxLayout()

        self.generate_button = QPushButton("Generate Wallet")
        self.generate_button.clicked.connect(self.generate_wallet)

        self.update_button = QPushButton("Update Balance")
        self.update_button.clicked.connect(self.update_balance)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_transaction)

        button_layout.addWidget(self.generate_button)
        button_layout.addWidget(self.update_button)
        button_layout.addWidget(self.send_button)

        layout.addLayout(button_layout)

        self.update_wallet_info()


    def change_currency(self):
        self.wallet.selected_currency = self.currency_combo_box.currentText()
        self.update_wallet_info()

    def generate_wallet(self):
        self.wallet.generate_wallet()
        QMessageBox.information(self, "Wallet Generated", f"Wallet address generated and saved: {self.wallet.address}")
        self.update_wallet_info()

    def update_balance(self):
        self.wallet.fetch_balance()

    def update_wallet_info(self):
        address = self.wallet.get_address()
        if address != "No address found":
            self.address_text.setPlainText(address)
            self.update_balance()
        else:
            self.address_text.setPlainText("Error: No address found")
            self.balance_text.setText("")
        self.update_price()

    def update_price(self):
        self.wallet.fetch_price()

    def send_transaction(self):
        recipient_address = self.recipient_text.text()
        amount = float(self.amount_text.text())
        if recipient_address and amount > 0:
            self.wallet.send_transaction(recipient_address, amount)
            QMessageBox.information(self, "Transaction Sent", "Transaction successfully sent.")
            # Optionally update wallet info or display confirmation to the user
        else:
            QMessageBox.warning(self, "Invalid Input", "Please enter a valid recipient address and amount.")

if __name__ == '__main__':
    app = QApplication([])
    app.setStyle("Fusion")
    gui = CryptoWalletGUI()
    gui.show()
    sys.exit(app.exec_())
