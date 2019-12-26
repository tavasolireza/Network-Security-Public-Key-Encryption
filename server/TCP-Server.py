import socketserver
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def generate_asymmetric_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key, private_key


def storing_keys(public_key, private_key):
    store_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    store_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return store_public, store_private


def info_file(username, user_public, server_private):
    print(user_public)
    with open('table.secret', 'a+') as f:
        f.write(f'{username}||||||{user_public}||||||{server_private}')


class ServerHandler(socketserver.BaseRequestHandler):
    public, private = generate_asymmetric_keys()
    rpublic, rprivate = storing_keys(public, private)
    username = ''
    user_public_key = ''
    action = ''
    session_key = ''

    def handle(self):
        try:
            while True:
                self.data = b''
                # self.request - TCP socket connected to the client
                self.data = self.request.recv(1024).strip()
                self.action = self.data[:9].decode()
                if self.action == 'snd_usrnm':
                    self.username = self.data[9:-271].decode()
                    self.user_public_key = self.data[-271:].decode()
                    # info_file(self.username, self.user_public_key, self.rprivate)
                    self.request.sendall(b'server_public' + self.rpublic)
                elif self.action == 'snd_sekey':
                    self.session_key = self.private.decrypt(
                        self.data[9:],
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    print(self.session_key)

                # self.request.sendall("ACK from TCP Server".encode())
        except KeyboardInterrupt:
            print('connection closed!')


if __name__ == "__main__":
    HOST, PORT = "localhost", 9982
    tcp_server = socketserver.TCPServer((HOST, PORT), ServerHandler)
    tcp_server.serve_forever()
