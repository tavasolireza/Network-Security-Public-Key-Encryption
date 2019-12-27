import socketserver
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import datetime as dt
import file_encrypt as fien
import hashlib
from Crypto.Cipher import AES


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
                self.enc_data = b''
                c_time = ' ' + str(dt.datetime.now()).split('.')[0]
                # self.request - TCP socket connected to the client
                self.data = self.request.recv(2048).strip()
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
                elif self.action == 'send_data':
                    self.data, MAC = self.data[9:].split(b'!!!hash!!!')[0], self.data[9:].split(b'!!!hash!!!')[1]
                    MAC = AES.new(self.session_key.rjust(32), AES.MODE_ECB).decrypt(MAC)
                    self.enc_data = self.data
                    f = open('received__file' + c_time, 'wb')
                    f.write(self.enc_data)
                    f.close()
                    try:
                        fien.decrypt(fien.getKey(self.session_key.decode()), 'received__file' + c_time)
                        os.remove('received__file' + c_time)
                        try:
                            ff = open('file' + c_time, 'rb').read()
                            if hashlib.sha1(ff).hexdigest()[:-8] == MAC.decode():
                                print('MAC is correct')
                            else:
                                self.request.sendall("MAC is incorrect. Send again.".encode())
                        except:
                            pass

                        # ff = open('file ' + c_time, 'rb').read()
                        # print('hashed data ' + hashlib.sha1(ff).hexdigest()[:-8])
                        # print('MAC ' + MAC)
                        # if hashlib.sha1(ff).hexdigest()[:-8] == MAC:
                        #     print('MAC is correct')
                        # else:
                        #     self.request.sendall("MAC is incorrect. Send again.".encode())

                    except Exception as e:
                        os.remove('received__file' + c_time)

                self.request.sendall("ACK from TCP Server".encode())
        except KeyboardInterrupt:
            print('connection closed!')


if __name__ == "__main__":
    HOST, PORT = "localhost", 9967
    tcp_server = socketserver.TCPServer((HOST, PORT), ServerHandler)
    tcp_server.serve_forever()
