"""
Combine rsa, DH, aes
"""

from DHService import DiffieHellman
from Encryptor import Encryptor
from Decryptor import Decryptor
from CryptoService import CryptoService

class FakeCryptoService(CryptoService):
    # for testing use

    def get_dh_pri_key(self):
        return self.dh.generate_private_key()

    def get_dh_pub_key(self, private_key):
        return self.dh.generate_public_key(private_key)

    def get_dh_secret(self, private_key, other_public_key):
        # TODO verify the other_public_key
        return self.dh.compute_secret(private_key, other_public_key)

    def sym_encrypt(self, secret, p_text):
        return self.encryptor.sym_encrypt(secret, p_text)

    def sym_decrypt(self, secret, c_text):
        return self.decryptor.sym_decrypt(secret, c_text)

    def rsa_decrypt(self, c_text):
        return self.decryptor.rsa_decrypt(c_text)

    def rsa_sign(self, msg):
        return self.decryptor.rsa_sign(msg)

    def rsa_encrypt(self, p_text):
        return self.encryptor.rsa_encrypt(p_text)


