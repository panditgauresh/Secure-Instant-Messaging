import pickle
import os.path as path
import os

def load_pickle_file(path):
    """

    :param path:
    :return:
    """
    if not path.isfile(path):
        raise Exception("The file doesn't exist! Path: {}".format(path))
    with open(path, 'rb') as f:
        obj = pickle.load(f)
    return obj

def save(path, obj, overwirte=False):
    """

    :param path:
    :param obj:
    :return:
    """
    if path.isfile(path) and not overwirte:
        raise Exception("The file name already exists!")
    with open(path, 'wb+') as f:
        pickle.dump(obj, f)

def get_rand(bytes):
    """

    :param bytes:
    :return: an integer representation of the random number
    """
    return int(os.urandom(bytes).encode('hex'), 16)


def load_config_file(path):
    """
    Load and parse the config file: (dh_param, {username: (password hash, salt)})
    :param path: path of the config file
    :return:
    """
    config = load_pickle_file(path)
    dh_param, user_cred_dict = config
    return dh_param, user_cred_dict


def load_df_param_from_file(path):
    """

    :param path:
    :return:
    """
    with open(path, 'r') as f:
        prime_str = f.read().replace('\n', '')
    print prime_str


if __name__ == '__main__':
    path = 'files/df_param'
    load_df_param_from_file(path)