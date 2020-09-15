from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

def aes_decrypt_file(key, filepath):
    encrypted = base64.b64decode(open(filepath, 'rb').read())
    return aes_decrypt(key, encrypted)

def aes_decrypt(key, encrypted_bytes):
    decryptor = Cipher(algorithms.AES(key.encode()), modes.ECB()).decryptor()
    decrypted = decryptor.update(encrypted_bytes)
    print(decrypted)
    return decrypted

aes_decrypt_file('YELLOW SUBMARINE', 'challenge7.txt')

