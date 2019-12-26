import socket

host_ip, server_port = "127.0.0.1", 9999

tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM, )


try:
    tcp_client.connect((host_ip, server_port))
    tcp_client.sendall(b'user sent data')

    while True:
        received = tcp_client.recv(1024)
        print("Bytes Received: {}".format(received.decode()))
except KeyboardInterrupt:
    print('connection closed by user')
finally:
    tcp_client.close()
