# code reference: https://github.com/lowazo/pyDHE/blob/master/DiffieHellman.py

import Utilities as util
import Consts as c

class DiffieHellman(object):
    """

    """
    def __init__(self, p, g):
        """

        :param key_path: the path of the DH key public parameters (g, p)
        :param key_length: private key length in bits
        :return:
        """
        self.prime = p
        self.generator = g


    def generate_private_key(self, bits=c.DH_KEY_SIZE):
        """

        :param bits:
        :return:
        """
        bytes = int(bits / 8)
        return util.get_rand(bytes)

    def generate_public_key(self, private_key):
        """

        :return: g ** private_key % p
        """
        return pow(self.generator, private_key, self.prime)

    def compute_secret(self, private_key, other_public_key):
        """
        other_public_key ** private_key % prime
        :param other_public_key:
        :return:
        """
        self.secret = pow(other_public_key, private_key, self.prime)
        return
