import socket
import threading


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 8001))
s.listen(100)

def handelConnection(conn, addr):
    while True:
        data = conn.recv(4096)
        if not data:
            return
        superPrint(data)

def superPrint(data):
    try:
        print(data.decode())
    except:
        print(data)

while True:
    conn, addr = s.accept()
    threading.Thread(target=handelConnection, args=(conn,addr)).start()

