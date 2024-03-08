import sys
import os
import hashlib
import ecdsa
import requests
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QTextEdit, QVBoxLayout, QPushButton,
    QComboBox, QMainWindow, QHBoxLayout, QMessageBox
)
from PyQt5.QtGui import QIcon, QFont, QColor, QPixmap
from PyQt5.QtCore import Qt
import base58

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

    def generate_wallet(self):
        self.private_key = self.generate_private_key()
        self.public_key = self.generate_public_key(self.private_key)
        self.address = self.generate_address(self.public_key, self.currencies[self.selected_currency]["explorer"])
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
        url = f"https://{self.currencies[self.selected_currency]['explorer']}/q/addressbalance/{self.address}"
        try:
            response = requests.get(url)
            response.raise_for_status()  # Raise an exception for bad responses (4xx or 5xx)
            balance_satoshis = int(response.text)
            self.balance = balance_satoshis / 100000000
        except requests.RequestException as e:
            print("Error fetching balance:", e)
            self.balance = None

    def fetch_price(self):
        try:
            response = requests.get(self.currencies[self.selected_currency]["price_api"])
            response.raise_for_status()  # Raise an exception for bad responses (4xx or 5xx)
            price_data = response.json()
            self.price = price_data[self.selected_currency.lower()]["usd"]
        except requests.RequestException as e:
            print("Error fetching price:", e)
            self.price = None

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

    @staticmethod
    def generate_address(public_key, explorer):
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashlib.sha256(public_key[0]).digest())
        hash160 = ripemd160.digest()
        address = CryptoWallet.hash160_to_p2pkh(hash160)
        return address

    @staticmethod
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

        header_label = QLabel("Manage Your Crypto Wallet")
        header_label.setAlignment(Qt.AlignCenter)
        header_font = QFont("Arial", 16, QFont.Bold)
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

        button_layout = QHBoxLayout()

        self.generate_button = QPushButton("Generate Wallet")
        self.generate_button.clicked.connect(self.generate_wallet)

        button_layout.addWidget(self.generate_button)

        layout.addLayout(button_layout)

        self.update_wallet_info()

        self.setStyleSheet("""
            QWidget {
                background-color: #f0f0f0;
            }
            QLabel {
                color: #333;
            }
            QTextEdit, QLineEdit {
                background-color: #fff;
                border: 1px solid #ccc;
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
        """)

    def change_currency(self):
        self.wallet.selected_currency = self.currency_combo_box.currentText()
        self.update_wallet_info()

    def generate_wallet(self):
        self.wallet.generate_wallet()
        self.update_wallet_info()
        QMessageBox.information(self, "Wallet Generated", "Wallet generated successfully!")

    def update_wallet_info(self):
        self.address_text.setPlainText(self.wallet.get_address())
        self.update_balance()
        self.update_price()

    def update_balance(self):
        self.wallet.fetch_balance()
        if self.wallet.balance is not None:
            self.balance_text.setText(f"{self.wallet.balance:.8f} {self.wallet.selected_currency}")
        else:
            self.balance_text.setText("Error fetching balance")

    def update_price(self):
        self.wallet.fetch_price()
        if self.wallet.price is not None:
            self.price_text.setText(f"${self.wallet.price:.2f}")
        else:
            self.price_text.setText("Error fetching price")


if __name__ == '__main__':
    app = QApplication([])
    app.setStyle("Fusion")  # Use Fusion style
    gui = CryptoWalletGUI()
    gui.show()
    app.exec_()
