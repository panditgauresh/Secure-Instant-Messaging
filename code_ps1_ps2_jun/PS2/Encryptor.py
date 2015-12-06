from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from KeyUtil import PrivateKeyUtil, PublicKeyUtil
import os
import Consts as c


class Encryptor():

    def __init__(self, d_pub_k_path, private_k_path):
        '''
        Initiate encryptor with the private key and public key
        :param d_pub_k_path:
        :param private_k_path:
        :return:
        '''
        self.dest_pub_key = PublicKeyUtil(d_pub_k_path)
        self.private_key = PrivateKeyUtil(private_k_path)

    def encrypt(self, p_text):

        # padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(p_text)
        padded_data += padder.finalize()

        # generate sym_key
        # encrypt with sym_key
        sym_key = os.urandom(c.SYM_KEY_LENGTH)
        iv = os.urandom(c.IV_LENGTH)
        cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_data) + encryptor.finalize()

        # sign the cipher_text with private key
        rsa_sign = self.private_key.sign(cipher_text)

        # generate digest for the cipher text with HMAC
        # key = os.urandom(32)
        # h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        # h.update(b"data")
        # sign = h.finalize()

        # encrypt header with public key
        encrypted_sym_key = self.dest_pub_key.encrypt(sym_key)

        # concate header: sym_key + iv + digest
        header = encrypted_sym_key + iv + rsa_sign

        # concate encrypt header + cipher text
        whole_msg = header + cipher_text

        return whole_msg
