import pickle
import os.path
import os
import datetime
import sys
import socket
import Consts as c
from PacketOrganiser import PacketOrganiser


def load_pickle_file(path):
    """

    :param path:
    :return:
    """
    if not os.path.isfile(path):
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
    if os.path.isfile(path) and not overwirte:
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
    return int(prime_str.encode('hex'), 16)

def add_time_stamp(out_msg):
    return str(out_msg) + datetime.datetime.now().strftime("%H:%M:%S:%f")

def isValidTimeStamp(message, indexOfMessage):
    timestamp = message.rsplit('\n',1)[1]
    recvTime = datetime.datetime.strptime(timestamp,"%H:%M:%S:%f")
    timeNow = datetime.datetime.now().strptime(timestamp,"%H:%M:%S:%f")
    # print(message)
    # print("timestamp")
    # print(timeNow)
    # print(recvTime)
    diff = timeNow - recvTime
    print(diff)
    #if(diff.days == 0 and diff.hours == 0 and diff.minutes == 0 and diff.seconds == 0):
    #  if(abs(diff.microseconds) < 500):
    if(diff.days == 0 and abs(diff) < datetime.timedelta(microseconds=200)):
        return True
        #print(diff.strftime("%H:%M:%S:%f"))
    print(diff)
    return False

def verifyNonce(msg,addr,nonce_dict):
    nonce = msg.rsplit('\n', 1)[1]
    if(nonce_dict[addr] == nonce):
        return True
    return False

def addNonce(out_msg,addr,nonce_dict):
    nonce_dict[addr] = get_rand(8)
    return str(out_msg) + "\n" + str(nonce_dict[addr])

def retrieveOrigMsg(out_msg):
    out_msg = out_msg.rsplit('\n',1)[0]
    # print("out Message:"+str(out_msg))
    return out_msg

def format_message(*args):
    res = ""
    for a in args:
        res += str(a) + ","
    return res[:-1]

def get_one_response(sock, addr):
    assert  isinstance(sock, socket.socket)
    recv_msg = None
    while True:
        # listening to the server and display the message
        recv_msg, r_addr = sock.recvfrom(c.SOCK_BUFFER)
        if r_addr == addr and recv_msg:
            break
    return recv_msg

def get_user_input(prompt):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    return sys.stdin.readline()[:-1]

def addr_to_str(addr):
    """

    :param addr:
    :return:
    """
    return str(addr[0]) + ":" + str(addr[1])

def str_to_addr(s):
    """

    :param s:
    :return:
    """
    ss = s.split(":")
    return (ss[0], int(ss[1]))

def display_user_message(raw_msg, username):
    """

    :param raw_msg:
    :param username:
    :return:
    """
    ts = PacketOrganiser.get_new_timestamp()
    msg = "{} <{}>: {}".format(username, ts, raw_msg)
    cmd_output(msg)

def cmd_output(msg):
    """

    :param msg:
    :return:
    """
    msg = "\r" + msg + "\n"
    sys.stdout.write(msg)
    sys.stdout.write(c.PROMPT)
    sys.stdout.flush()

def get_good_nonce(dict):
    nonce = PacketOrganiser.genRandomNumber()
    while nonce in dict:
        nonce = PacketOrganiser.genRandomNumber()
    return nonce

def add_to_request_cache(cache, nonce, type, key, msg, addr, auth=None):
    """

    :param cache:
    :param nonce:
    :param type:
    :param key:
    :param msg:
    :param addr:
    :param auth:
    :return:
    """
    if nonce in cache:
        raise Exception(c.WARNING_EXISTED_NONCE)
    cache[nonce] = [type, key, msg, addr, PacketOrganiser.get_new_timestamp()]
    if auth:
        cache[nonce].append(auth)
    # print("current request_cache: {}".format(cache))

def replace_ts_in_msg(msg):
    """

    :param msg:
    :return:
    """
    msg_without_ts = msg[:-c.TS_LEN]
    new_msg = msg_without_ts + PacketOrganiser.get_new_timestamp()
    return new_msg

def send_confirmation(sock, crypto_service, key, n, r_addr, second_part=None):

    if second_part:
        conf_msg_parts = [c.MSG_RESPONSE_OK, second_part, ""]
    else:
        conf_msg_parts = c.MSG_RESPONSE_OK

    conf_msg = PacketOrganiser.prepare_packet(conf_msg_parts, n)
    enc_conf_msg = crypto_service.sym_encrypt(key, conf_msg)
    sock.sendto(enc_conf_msg, r_addr)

if __name__ == '__main__':
    # path = 'files/df_param'
    # print load_df_param_from_file(path)
    print format_message(1, 2, 3)