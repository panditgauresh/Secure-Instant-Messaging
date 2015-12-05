import Utilities as util
import Consts as c

class DiffieHellman(object):
    """

    """
    def __init__(self, p, g, key_length=c.DF_KEY_SIZE):
        """

        :param key_path: the path of the DH key public parameters (g, p)
        :param key_length: private key length in bits
        :return:
        """
        self.generator = g
        self.prime = p
        self.private_key = self._generate_private_key(key_length)
        self.public_key = self._generate_public_key()
        self.secret = None

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

    def compute_secret(self, other_public_key):
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


# code reference: https://github.com/lowazo/pyDHE/blob/master/DiffieHellman.py
