from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from KeyUtil import PrivateKeyUtil, PublicKeyUtil
import Consts as c


class Decryptor():
    sender_pub_key = None
    private_key = None

    def __init__(self, private_k_path):
        '''
        Initiate encryptor with the private key and public key
        :param private_k_path:
        :return:
        '''
        self.private_key = PrivateKeyUtil(private_k_path) if private_k_path is not None else None

    def rsa_decrypt(self, c_text):
        if len(c_text) > c.C_TEXT_LEN_4096:
            c_text_1 = c_text[:c.C_TEXT_LEN_4096]
            c_text_2 = c_text[c.C_TEXT_LEN_4096:]
            p_text_1 = self.private_key.decrypt(c_text_1)
            p_text_2 = self.private_key.decrypt(c_text_2)
            p_text = p_text_1 + p_text_2
        else:
            p_text = self.private_key.decrypt(c_text)
        return p_text


    def sym_decrypt(self, secret, c_file):

        # separate the header and content from c_text
        c_header = c_file[:c.HEADER_LENGTH]
        c_text = c_file[c.HEADER_LENGTH:]

        # parse header to get digest
        iv = c_header

        # decrypt the cipher text
        cipher = Cipher(algorithms.AES(secret), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        p_text = decryptor.update(c_text) + decryptor.finalize()

        # unpadding
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(p_text)
        unpadded_data += unpadder.finalize()
        return unpadded_data


    def parse_header(self, header):
        # TODO exception handling
        iv = header
        return iv

    def rsa_sign(self, msg):
        sign = self.private_key.sign(msg)
        return sign


