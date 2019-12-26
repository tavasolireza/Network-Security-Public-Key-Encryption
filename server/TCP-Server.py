import socketserver


class ServerHandler(socketserver.BaseRequestHandler):

    def handle(self):
        try:
            while True:
                # self.request - TCP socket connected to the client
                self.data = self.request.recv(1024).strip()
                print(self.data)
                self.request.sendall("ACK from TCP Server".encode())
        except KeyboardInterrupt:
            print('connection closed!')



if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    tcp_server = socketserver.TCPServer((HOST, PORT), ServerHandler)
    tcp_server.serve_forever()
