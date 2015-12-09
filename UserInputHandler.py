"""
Handle the user input including LIST, send message to someone
"""
import re
import Consts as c
from PacketOrganiser import PacketOrganiser
from CryptoService import CryptoService

class UserInputHandler(object):

    def __init__(self, client_auth):
        self.auth = client_auth
        self.serv = CryptoService()

    def handle_input(self, msg, packetorg, users, serv_addr):
        """

        :param input:
        :return:
        """
        # LIST, CHAT
        msg = msg[:-1]
        match_res = re.match(c.USR_CMD_RE, msg)
        if not match_res:   #Reply from server or chat client
            return None, None
        if msg == c.USR_CMD_LIST:
            res_msg = PacketOrganiser.prepare_packet(c.USR_CMD_LIST, PacketOrganiser.genRandomNumber())
            # ts_msg = packetorg.addTimeStamp(msg)
            return c.USR_CMD_LIST, serv_addr, self.serv.sym_encrypt(self.auth.dh_key, res_msg)
        else:
            username, chat_msg = packetorg.get_user_message(msg)
            if username in users:
                addr, key, nonce = users[username]

                if chat_msg == "":
                    return None, None
                return None, addr, self.serv.sym_encrypt(key, chat_msg)
            elif username:
                 return username, serv_addr, packetorg.addNonce(packetorg.addTimeStamp(username))
            else:
                return None, c.ERR_CMD_CHAT