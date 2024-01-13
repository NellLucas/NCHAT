import socket
import threading

# 서버 IP/PORT
HOST = '127.0.0.1'
PORT = 11432

clients = []
lock = threading.Lock()

# 서버 소켓 생성
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # 소켓 유형 설정
server_socket.bind((HOST, PORT)) # IP 주소와 포트를 소켓으로 묶기
server_socket.listen() # 클라이언트의 소켓 기다리기

print(f"서버가 {HOST}:{PORT}에서 대기 중입니다.")

# 클라이언트 - 서버 연결 관리
def handle_client(client_socket, addr):
    with lock:
        clients.append(client_socket)

    while True:
        data = client_socket.recv(1024).decode() # 데이터 받기
        if not data:
            break
        data = f"({addr[0]}:{addr[1]}) : " + data
        print(data)
        broadcast(data, client_socket)

    with lock:
        clients.remove(client_socket)
    client_socket.close() # 소켓 종료

# 모든 클라이언트에게 메시지 전송(Broadcast)
def broadcast(message, client_socket):
    with lock:
        for client in clients:
            if client != client_socket:
                try:
                    client.send(message.encode()) # 데이터 보내기
                except:
                    client.close()
                    clients.remove(client)


while True: # Main 쓰레드
    client_socket, addr = server_socket.accept()
    print(f"새로운 연결: {addr[0]}:{addr[1]}")
    client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
    client_handler.start()
