# server.py
import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

HOST = '0.0.0.0'
PORT = 19132

clients = []
lock = threading.Lock()

# RSA 키 쌍 공유
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# 키 직렬화
public_key = private_key.public_key()
serialized_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def encrypt(message, client_public_key):
    # 메시지 암호화
    encrypted_message = client_public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def decrypt(encrypted_message):
    # 메시지 복호화
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

def handle_client(client_socket, addr):
    with lock:
        clients.append(client_socket)

    # Public key 공유
    client_socket.sendall(serialized_public_key)

    # 클라이언트 key 수신
    serialized_client_public_key = client_socket.recv(2048)
    client_public_key = serialization.load_pem_public_key(
        serialized_client_public_key,
        backend=default_backend()
    )

    while True:
        encrypted_data = client_socket.recv(2048)
        if not encrypted_data:
            break

        decrypted_data = decrypt(encrypted_data)
        data = f"({addr[0]}:{addr[1]}) : " + decrypted_data
        print(data)

        encrypted_data = encrypt(data, client_public_key)
        broadcast(encrypted_data, client_socket)

    with lock:
        clients.remove(client_socket)
    client_socket.close()

def broadcast(message, client_socket):
    with lock:
        for client in clients:
            if client != client_socket:
                try:
                    client.sendall(message)
                except:
                    client.close()
                    clients.remove(client)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()

print(f"서버가 {HOST}:{PORT}에서 대기 중입니다.")

while True:
    client_socket, addr = server_socket.accept()
    print(f"새로운 연결: {addr[0]}:{addr[1]}")
    client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
    client_handler.start()