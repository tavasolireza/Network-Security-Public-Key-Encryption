import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random


def encrypt(key, filename):
    chunk_size = 64 * 1024
    output_file = 'encrypted_' + filename
    file_size = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    with open(filename, 'rb') as infile:
        with open(output_file, 'wb') as outfile:
            outfile.write(file_size.encode('utf-8'))
            outfile.write(IV)
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))
                outfile.write(encryptor.encrypt(chunk))

    outfile.close()
    infile.close()


def decrypt(key, filename):
    chunk_size = 64 * 1024
    output_file = filename[10:]
    with open(filename, 'rb') as infile:
        file_size = int(infile.read(16))
        IV = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        with open(output_file, 'wb') as outfile:
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(file_size)
    outfile.close()
    infile.close()


def getKey(password):
    hashed_passwords = SHA256.new(password.encode('utf-8'))
    return hashed_passwords.digest()


def main():
    choice = input('Would you like to (E)ncrypt or (D)ecrypt?: ')
    if choice == 'E' or choice == 'e':
        filename = input('File to encrypt: ')
        password = input('Password: ')
        encrypt(getKey(password), filename)
        print('Done.')
    elif choice == 'D' or choice == 'd':
        filename = input('File to decrypt: ')
        password = input('Password: ')
        decrypt(getKey(password), filename)
        print('Done.')
    else:
        print('No Option selected, closing…')


if __name__ == '__main__':
    main()
