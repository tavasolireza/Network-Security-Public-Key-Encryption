import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

host_ip, server_port = "127.0.0.1", 9982
tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM, )

username = input('Username: ')


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


def public_key_encrypt(server_key, message):
    message = message.encode()
    public_key = serialization.load_pem_public_key(
        server_key,
        backend=default_backend()
    )

    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


try:
    server_public_key = b''
    tcp_client.connect((host_ip, server_port))
    public, private = generate_asymmetric_keys()
    rpublic, rprivate = storing_keys(public, private)

    tcp_client.sendall(b'snd_usrnm' + username.encode() + rpublic)
    received = tcp_client.recv(1024)
    if received.startswith(b'server_public'):
        server_public_key = received[13:]

    print(server_public_key)
    session_key = input('enter session key: ')
    print(len(public_key_encrypt(server_public_key, session_key)))
    print()
    tcp_client.sendall(b'snd_sekey' + public_key_encrypt(server_public_key, session_key))

    # while True:
    #     received = tcp_client.recv(1024)
    #     print("Bytes Received: {}".format(received.decode()))
except KeyboardInterrupt:
    print('connection closed by user')
finally:
    tcp_client.close()
