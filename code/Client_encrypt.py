import sys
import socket
import threading
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QVBoxLayout, QWidget, QLineEdit
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# 서버 IP/PORT 설정
HOST = '132.226.22.163'
PORT = 19132

class ChatClient(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()
        self.initSocket()
        self.perform_key_exchange()

    # PyQt5 UI
    def initUI(self):
        self.setWindowTitle('Chat 프로그램')
        self.setGeometry(100, 100, 400, 400)

        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout()

        self.text_box = QTextEdit(self)
        self.text_box.setReadOnly(True)
        self.layout.addWidget(self.text_box)

        self.input_box = QLineEdit(self)
        self.input_box.returnPressed.connect(self.send_message)
        self.layout.addWidget(self.input_box)

        self.send_button = QPushButton('보내기', self)
        self.send_button.clicked.connect(self.send_message)
        self.layout.addWidget(self.send_button)

        self.central_widget.setLayout(self.layout)
    # 클라이언트 소켓 및 RSA 키 생성
    def initSocket(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT))

        # RSA 키 쌍 생성
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # 키 직렬화
        self.public_key = self.private_key.public_key()
        serialized_public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # RSA 키 전송
        self.client_socket.sendall(serialized_public_key)

    # RSA 키 교환 수행
    def perform_key_exchange(self):
        # 서버 Public key 수신
        serialized_server_public_key = self.client_socket.recv(2048)
        server_public_key = serialization.load_pem_public_key(
            serialized_server_public_key,
            backend=default_backend()
        )

        self.server_public_key = server_public_key

    # 메시지 수신
    def receive_message(self):
        while True:
            try:
                encrypted_data = self.client_socket.recv(2048)
                if not encrypted_data:
                    break

                decrypted_data = self.decrypt(encrypted_data)
                self.text_box.append(decrypted_data)
            except Exception as e:
                print(e)
                break

    # 메시지 전송 및 RSA 암호화
    def send_message(self):
        message = self.input_box.text()
        if message.lower() == 'quit':
            self.client_socket.send(message.encode())
            self.client_socket.shutdown(socket.SHUT_WR)
            self.client_socket.close()
            sys.exit("NCHAT has ended.")
        elif message:
            encrypted_message = self.encrypt(message, self.server_public_key)
            self.client_socket.sendall(encrypted_message)
            self.input_box.clear()
            message = "(ME) : " + message
            self.text_box.append(message)

    # RSA 암호화
    def encrypt(self, message, public_key):
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message

    # RSA 복호화
    def decrypt(self, encrypted_message):
        decrypted_message = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    client = ChatClient()
    client.show()
    sys.exit(app.exec_())
