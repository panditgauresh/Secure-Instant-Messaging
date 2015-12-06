# code reference: https://github.com/lowazo/pyDHE/blob/master/DiffieHellman.py


import Utilities as util
import Consts as c

class DiffieHellman(object):
    """

    """
    def __init__(self, p, g, key_length=c.DH_KEY_SIZE):
        """

        :param key_path: the path of the DH key public parameters (g, p)
        :param key_length: private key length in bits
        :return:
        """
        self.generator = g
        self.prime = p
        self.key_length = key_length
        self.private_key = 0
        self.public_key = 0
        self.secret = None

    def feed_other_public_key(self, other_pub_k):
        """

        :param other_pub_k:
        :return:
        """
        self.private_key = self._generate_private_key(self.key_length)
        self.public_key = self._generate_public_key()
        self._compute_secret(other_pub_k)
        return self.secret

    def _generate_private_key(self, bits):
        """

        :param bits:
        :return:
        """
        bytes = int(bits / 8)
        return util.get_rand(bytes)

    def _generate_public_key(self):
        """

        :return: g ** private_key % p
        """
        return pow(self.generator, self.private_key, self.prime)

    def _compute_secret(self, other_public_key):
        """
        other_public_key ** private_key % prime
        :param other_public_key:
        :return:
        """
        self.secret = pow(other_public_key, self.private_key, self.prime)
        return

    def get_secret(self):
        """
        Getter for shared secret
        :return:
        """
        return self.secret


