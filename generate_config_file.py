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
    param = (generator_list[c.DF_GENERATOR_INDEX], get_prime(c.DF_PRIME_SIZE))
    util.save(path, param)




if __name__ == '__main__':
    pass

