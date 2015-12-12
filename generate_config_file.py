# this file is to use for generate config file which contains DF parameters
# and the encrypted username/password pairs

import ssl
import os
import Consts as c
import Utilities as util
import hashlib

generator_list = [2, 3, 5, 7]

def get_prime(bits):

    pass

def generate_DF_param_file(path):
    """

    :param path:
    :return:
    """
    param = (c.DH_GENERATOR, get_prime(c.DH_PRIME_SIZE))
    util.save(path, param)


def generate_password_hash_dict(path):
    pw_dict = {"alice" : "ILoveNS201%",
               "bob" : "Ns15Fall!@11",
               "coco" : "CS674)Awesome",
               "derek" : "Go0dPasswor$",
               "eli" : "bAdPassw0r&"}
    pw_hash_dict = {}
    for u in pw_dict:
        salt = os.urandom(6)
        pw_hash_dict[u] = (hashlib.sha256(pw_dict[u] + salt).hexdigest(), salt)

    util.save(path, pw_hash_dict, True)

if __name__ == '__main__':
    # generate dh param
    # dh_path = c.DH_CONFIG_PATH
    # generate_DF_param_file(dh_path)

    pw_path = c.PW_HASH_PATH
    generate_password_hash_dict(pw_path)

