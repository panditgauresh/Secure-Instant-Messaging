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
    param = (generator_list[c.DH_GENERATOR_INDEX], get_prime(c.DH_PRIME_SIZE))
    util.save(path, param)


def generate_and_save_config_file(path):
    """

    :param path:
    :return:
    """

    # get parameters for DH
    df_path = 'files/df_param'
    prime = util.load_df_param_from_file(df_path)
    g = 2
    df_param = (g, prime)

    # get user dict
    user_dict = {}
    # TODO generate user/password hashed and salt

def generate_password_hash_dict(path):
    pw_dict = {"user1" : "CS6740",
               "user2" : "cs6740",
               "admin" : "admin123"}
    pw_hash_dict = {}
    for u in pw_dict:
        salt = os.urandom(6)
        pw_hash_dict[u] = (hashlib.sha256(pw_dict[u] + salt).hexdigest(), salt)

    util.save(path, pw_hash_dict)

if __name__ == '__main__':
    pw_path = "files/pw_hash_dict"
    # generate_password_hash_dict(pw_path)
    d = util.load_pickle_file(pw_path)
    print(d["admin"])

