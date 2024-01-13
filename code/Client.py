import socket
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QVBoxLayout, QWidget, QLineEdit
import threading

# 서버 IP/PORT 설정
HOST = '132.226.22.163'
PORT = 19132

class ChatClient(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()
        self.initSocket()
    #PyQt5 UI
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
    #클라이언트 소켓 생성
    def initSocket(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT)) # 소켓 연결

        self.receive_thread = threading.Thread(target=self.receive_message)
        self.receive_thread.daemon = True
        self.receive_thread.start()
    #메시지 수신
    def receive_message(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode() # 소켓 수신
                self.text_box.append(message)
            except Exception as e:
                print(e)
                break
    # 메시지 전송
    def send_message(self):
        message = self.input_box.text()
        if message.lower() == 'quit':
            self.client_socket.send(message.encode())
            self.client_socket.shutdown(socket.SHUT_WR)  # Send TCP FIN Socket
            self.client_socket.close()
            sys.exit("NCHAT has ended.")
        elif message:
            self.client_socket.send(message.encode()) # 소켓 송신
            self.input_box.clear()
            message = "(ME) : " + message
            self.text_box.append(message)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    client = ChatClient()
    client.show()
    sys.exit(app.exec_())
