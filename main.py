import sys
import os
import hashlib
import ecdsa
import qrcode
import requests
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QTextEdit, QVBoxLayout, QPushButton, QComboBox, QMainWindow, QMessageBox
from PyQt5.QtGui import QIcon, QPixmap, QFont
from PyQt5.QtCore import Qt
from pycoin.key import Key
from PyQt5 import QtWidgets

class CryptoWallet:
    def __init__(self):
        self.currencies = {
            "Bitcoin": {"explorer": "blockchain.com", "price_api": "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"},
            "Ethereum": {"explorer": "etherscan.io", "price_api": "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"},
            # Add more cryptocurrencies here
        }
        self.selected_currency = "Bitcoin"
        self.private_key = None
        self.public_key = None
        self.address = None
        self.balance = None
        self.price = None
        self.transactions = None

    def generate_wallet(self):
        # Placeholder functions for generating private key, public key, and address
        self.private_key = generate_private_key()
        self.public_key = generate_public_key(self.private_key)
        self.address = generate_address(self.public_key, self.currencies[self.selected_currency]["explorer"])
        print("Generated address:", self.address)  # Print the generated address

    def get_address(self):
        return self.address

    def get_private_key(self):
        return self.private_key

    def fetch_balance(self):
        # Fetch balance from blockchain explorer API
        url = f"https://{self.currencies[self.selected_currency]['explorer']}/q/addressbalance/{self.address}"
        print("Balance URL:", url)  # Print the URL being used
        response = requests.get(url)
        print("Response status code:", response.status_code)  # Print the response status code
        if response.status_code == 200:
            balance_satoshis = int(response.text)
            self.balance = balance_satoshis / 100000000  # Convert from satoshis to BTC
        else:
            self.balance = None

    def fetch_price(self):
        # Fetch current cryptocurrency price from CoinGecko API
        response = requests.get(self.currencies[self.selected_currency]["price_api"])
        if response.status_code == 200:
            price_data = response.json()
            self.price = price_data[self.selected_currency.lower()]["usd"]
        else:
            self.price = None

    def fetch_transactions(self):
        # Fetch transaction history from blockchain explorer API
        response = requests.get(f"https://{self.currencies[self.selected_currency]['explorer']}/rawaddr/{self.address}")
        if response.status_code == 200:
            transactions_data = response.json()
            self.transactions = transactions_data["txs"]
        else:
            self.transactions = None

    @staticmethod
    def generate_private_key():
        # Generate a secure random Bitcoin private key using os.urandom
        key_bytes = os.urandom(32)
        key_int = int.from_bytes(key_bytes, byteorder='big')
        return key_int

    @staticmethod
    def generate_public_key(private_key):
        # Derive the corresponding uncompressed and compressed public keys from the private key
        sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, byteorder='big'), curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        uncompressed_public_key = b'\x04' + vk.to_string()
        compressed_public_key = b'\x02' + bytes([vk.y % 2 + 2]) + vk.to_string()
        return uncompressed_public_key, compressed_public_key

    @staticmethod
    def generate_address(public_key, explorer):
        # Generate Bitcoin address from public key
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashlib.sha256(public_key).digest())
        hash160 = ripemd160.digest()
        address = Key.from_text('BTC', public_key).address(use_uncompressed=False)
        return address


class CryptoWalletGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.wallet = CryptoWallet()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Crypto Wallet")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QIcon("icon.png"))  # Placeholder icon
        self.setStyleSheet("background-color: #333333; color: #ffffff;")

        layout = QVBoxLayout()

        self.currency_label = QLabel("Select Currency:")
        self.currency_combo_box = QComboBox()
        for currency in self.wallet.currencies:
            self.currency_combo_box.addItem(currency)
        self.currency_combo_box.currentIndexChanged.connect(self.change_currency)
        self.currency_combo_box.setStyleSheet("QComboBox { background-color: #444444; color: #ffffff; }"
                                              "QComboBox::drop-down { border: none; }"
                                              "QComboBox::down-arrow { image: url(down_arrow.png); }")

        self.address_label = QLabel("Wallet Address:")
        self.address_text = QTextEdit()
        self.address_text.setReadOnly(True)
        self.address_text.setStyleSheet("background-color: #444444; color: #ffffff; border: 1px solid #666666;")
        self.address_text.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)

        self.balance_label = QLabel("Balance:")
        self.balance_text = QLabel()
        self.balance_text.setStyleSheet("background-color: #444444; color: #ffffff;")
        self.balance_text.setFont(QFont("Arial", 12, QFont.Bold))

        self.price_label = QLabel("Current Price (USD):")
        self.price_text = QLabel()
        self.price_text.setStyleSheet("background-color: #444444; color: #ffffff;")
        self.price_text.setFont(QFont("Arial", 12, QFont.Bold))

        self.generate_button = QPushButton("Generate Wallet")
        self.generate_button.setStyleSheet("background-color: #009688; color: #ffffff; border: none; padding: 10px;")

        layout.addWidget(self.currency_label)
        layout.addWidget(self.currency_combo_box)
        layout.addWidget(self.address_label)
        layout.addWidget(self.address_text)
        layout.addWidget(self.balance_label)
        layout.addWidget(self.balance_text)
        layout.addWidget(self.price_label)
        layout.addWidget(self.price_text)
        layout.addWidget(self.generate_button)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        self.generate_button.clicked.connect(self.generate_wallet)

        self.update_wallet_info()

    def change_currency(self):
        self.wallet.selected_currency = self.currency_combo_box.currentText()

    def generate_wallet(self):
        self.wallet.generate_wallet()
        self.update_wallet_info()

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
    app = QApplication(sys.argv)
    gui = CryptoWalletGUI()
    gui.show()
    sys.exit(app.exec_())
