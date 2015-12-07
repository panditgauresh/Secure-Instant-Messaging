"""
Combine rsa, DH, aes
"""

from DHService import DiffieHellman
from Encryptor import Encryptor
from Decryptor import Decryptor
from CryptoService import CryptoService
import Utilities as util
import socket



key_path = "files/key"

class FakeCryptoService(CryptoService):
    # for testing use

    def get_dh_pri_key(self):
        return self.dh.generate_private_key()

    def get_dh_pub_key(self, private_key):
        return self.dh.generate_public_key(private_key)

    def get_dh_secret(self, private_key, other_public_key):
        # TODO verify the other_public_key
        key = util.load_pickle_file(key_path)
        return key

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

if __name__ == '__main__':
    key = util.load_pickle_file(key_path)
    pw_dict_path = "files/pw_hash_dict"
    pw_dict = util.load_pickle_file(pw_dict_path)
    pw_hash = pw_dict["admin"][0]
    fcs = FakeCryptoService()
    msg = pw_hash + ",654"
    enc_msg = fcs.sym_encrypt(key, msg)
    # print(enc_msg)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local_ip = socket.gethostbyname(socket.gethostname())
    client_addr = (local_ip, 55056)
    server_addr = (local_ip, 9090)
    sock.bind(client_addr)
    sock.sendto(enc_msg, server_addr)


