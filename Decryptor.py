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
        self.private_key = PrivateKeyUtil(private_k_path)

    def rsa_decrypt(self, c_file):

        # separate the header and content from c_text
        c_header = c_file[:c.HEADER_LENGTH]
        c_text = c_file[c.HEADER_LENGTH:]

        # parse header to get sym_key and digest
        sym_key, iv = self.parse_header(c_header)

        # decrypt the cipher text
        cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        p_text = decryptor.update(c_text) + decryptor.finalize()

        # unpadding
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(p_text)
        unpadded_data += unpadder.finalize()
        return unpadded_data


    def sym_decrypt(self, c_file):

        # separate the header and content from c_text
        c_header = c_file[:c.HEADER_LENGTH]
        c_text = c_file[c.HEADER_LENGTH:]

        # parse header to get sym_key and digest
        sym_key, iv = self.parse_header(c_header)

        # decrypt the cipher text
        cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        p_text = decryptor.update(c_text) + decryptor.finalize()

        # unpadding
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(p_text)
        unpadded_data += unpadder.finalize()
        return unpadded_data


    def parse_header(self, header):
        # TODO exception handling
        enc_sym_key = header[:c.ENC_SYM_KEY_LENGTH]
        dec_sym_key = self.private_key.decrypt(enc_sym_key)
        iv = header[c.ENC_SYM_KEY_LENGTH:c.ENC_SYM_KEY_LENGTH+c.IV_LENGTH]
        return dec_sym_key, iv

    def rsa_sign(self, msg):
        self.private_key.sign(msg)
