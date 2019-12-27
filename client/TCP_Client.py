import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import file_encrypt as fien
import hashlib
from Crypto.Cipher import AES
import datetime

host_ip, server_port = "127.0.0.1", 9965
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


def data_exchange(se_key):
    sent_data = b'send_data'
    file = input('Enter filename: ')
    original_file = open(file, 'rb').read()
    hash_data = hashlib.sha1(original_file).hexdigest()[:-8]
    hash_data = AES.new(se_key.rjust(32), AES.MODE_ECB).encrypt(hash_data)
    fien.encrypt(fien.getKey(se_key), file)
    enc_file_name = 'encrypted_' + file
    f = open(enc_file_name, 'rb')
    encrypted_file = f.read()
    f.close()
    sent_data += encrypted_file
    print(sent_data)
    sent_data += b'!!!hash!!!' + hash_data
    print(sent_data)
    return sent_data


try:
    server_public_key = b''
    tcp_client.connect((host_ip, server_port))
    s_time = datetime.datetime.now()
    public, private = generate_asymmetric_keys()
    rpublic, rprivate = storing_keys(public, private)

    tcp_client.sendall(b'snd_usrnm' + username.encode() + rpublic)
    received = tcp_client.recv(1024)
    if received.startswith(b'server_public'):
        server_public_key = received[13:]

    session_key = input('enter session key: ')
    tcp_client.sendall(b'snd_sekey' + public_key_encrypt(server_public_key, session_key))

    while True:
        data = ''
        f_time = datetime.datetime.now()
        if (f_time - s_time).total_seconds() > 15:
            print('## Session key expired ##')
            session_key = input('enter new session key: ')
            tcp_client.sendall(b'snd_sekey' + public_key_encrypt(server_public_key, session_key))
            s_time = datetime.datetime.now()
        else:
            choose_action = input('Type \'d\' to send data: ')
            if choose_action == 'd':
                data = data_exchange(session_key)
            tcp_client.sendall(data)
            received = tcp_client.recv(1024)
            if received.decode().startswith('MAC'):
                data = data_exchange(session_key)

        print("Bytes Received: {}".format(received.decode()))
except KeyboardInterrupt:
    print('connection closed by user')
finally:
    tcp_client.close()
