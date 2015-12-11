"""
Combine rsa, DH, aes
"""

from DHService import DiffieHellman
from Encryptor import Encryptor
from Decryptor import Decryptor
import hashlib
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

class CryptoService(object):
    def __init__(self, rsa_pub_path=None, rsa_pri_path=None, p=None, g=None):
        self.dh = DiffieHellman(p, g) if p is not None and g is not None else None
        self.encryptor = Encryptor(rsa_pub_path)
        self.decryptor = Decryptor(rsa_pri_path)

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

    def rsa_verify(self, msg, sign):
        return self.encryptor.rsa_verify(msg, sign)

    def rsa_encrypt(self, p_text):
        return self.encryptor.rsa_encrypt(p_text)

    def compute_pw_hash(self, pw, salt):
        return hashlib.sha256(pw + salt).hexdigest()

    def new_sym_key(self, size=32):
        return os.urandom(size)

    @staticmethod
    def generate_hmac_sign(dh_key, msg):
        #generate digest for the cipher text with HMAC
        h = hmac.HMAC(dh_key, hashes.SHA256(), backend=default_backend())
        h.update(msg)
        sign = h.finalize()
        # print "Signature is:" + str(len(sign)) + ":" + sign
        return sign

    @staticmethod
    def verify_hmac_sign(dh_key, msg, sign):
        expect_sign = CryptoService.generate_hmac_sign(dh_key, msg)
        return expect_sign == sign
