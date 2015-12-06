# this file is to use for generate config file which contains DF parameters
# and the encrypted username/password pairs

import ssl
import os
import Consts as c
import Utilities as util

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



if __name__ == '__main__':
    pass

