from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from KeyUtil import PublicKeyUtil
import os
import Consts as c


class Encryptor():

    def __init__(self, d_pub_k_path):
        '''
        Initiate encryptor with the private key and public key
        :param d_pub_k_path:
        :param private_k_path:
        :return:
        '''
        self.dest_pub_key = PublicKeyUtil(d_pub_k_path) if d_pub_k_path is not None else None

    def rsa_encrypt(self, p_text):
        # TODO need to rewrite
        if len(p_text) > c.P_TEXT_LEN_4096:
            p_text_1 = p_text[:c.P_TEXT_LEN_4096]
            p_text_2 = p_text[c.P_TEXT_LEN_4096:]
            c_text_1 = self.dest_pub_key.encrypt(p_text_1)
            c_text_2 = self.dest_pub_key.encrypt(p_text_2)
            c_text = c_text_1 + c_text_2
        else:
            c_text = self.dest_pub_key.encrypt(p_text)

        return c_text

    def rsa_verify(self, msg, sign):
        return self.dest_pub_key.verify(msg, sign)

    def sym_encrypt(self, secret, p_text):

        # padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(p_text)
        padded_data += padder.finalize()

        # generate sym_key
        # encrypt with sym_key
        iv = os.urandom(c.IV_LENGTH)
        cipher = Cipher(algorithms.AES(secret), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_data) + encryptor.finalize()

        # concate header: sym_key + iv + digest
        header = iv

        # concate encrypt header + cipher text
        whole_msg = header + cipher_text

        return whole_msg

if __name__ == '__main__':
    enc = Encryptor(c.PUB_KEY_PATH)
    p_text = os.urandom(877)
    c_text = enc.rsa_encrypt(p_text)
    print(len(c_text))