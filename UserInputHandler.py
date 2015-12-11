"""
Handle the user input including LIST, send message to someone
"""
import re
import Consts as c
from PacketOrganiser import PacketOrganiser
from CryptoService import CryptoService
from ClientClientAuthentication import ClientClientAuthentication
import Utilities as util


class UserInputHandler(object):

    def __init__(self, server_auth, user_addr_dict, addr_auths, nonce_auths, active_users):
        self.auth = server_auth
        self.user_addr_dict = user_addr_dict
        self.addr_auths = addr_auths
        self.nonce_auths = nonce_auths
        self.active_users = active_users
        self.serv = CryptoService()

    def handle_input(self, msg, packetorg):
        """

        :param input:
        :return:
        """
        # LIST, CHAT
        msg = msg[:-1]
        match_res = re.match(c.USR_CMD_RE, msg)
        if not match_res:   #Reply from server or chat client
            return None, None, c.ERR_CMD_CHAT
        if msg == c.USR_CMD_LIST:
            nonce = util.get_good_nonce({}) # TODO need to change to actual nonce dict
            res_msg = PacketOrganiser.prepare_packet(c.MSG_TYPE_LIST, nonce)
            # ts_msg = packetorg.addTimeStamp(msg)
            return c.MSG_TYPE_LIST, self.auth.server_addr, self.serv.sym_encrypt(self.auth.dh_key, res_msg)
        elif match_res.group("chat") == c.USR_CMD_CHAT:
            username = match_res.group("username")
            chat_msg = match_res.group("msg")
            if username in self.user_addr_dict:
                # send the message to user
                addr = self.user_addr_dict[username]
                auth = self.addr_auths[addr]
                key = auth.dh_key
                nonce = PacketOrganiser.genRandomNumber()  # TODO add nonce to some nonce dict
                auth.last_nonce = nonce
                msg_to_send = PacketOrganiser.prepare_packet([c.MSG_TYPE_MSG, chat_msg, ""], nonce=nonce)
                encrypt_msg = self.serv.sym_encrypt(key, msg_to_send)
                msg = PacketOrganiser.add_sign(key, encrypt_msg)
                return None, addr, msg
            elif username in self.active_users:
                # start peer authentication
                nonce = PacketOrganiser.genRandomNumber()
                while nonce in self.nonce_auths:   # avoid key conflict
                    nonce = PacketOrganiser.genRandomNumber()
                self.nonce_auths[nonce] = ClientClientAuthentication(username, self.auth.crypto_service, chat_msg)
                key = self.auth.dh_key
                msg_to_send = PacketOrganiser.prepare_packet([c.MSG_TYPE_START_NEW_CHAT, username, ""], nonce=nonce)
                return username, self.auth.server_addr, self.serv.sym_encrypt(key, msg_to_send)
            else:
                return None, None, c.ERR_CMD_NO_USER
        else:
            return None, None, c.ERR_CMD_CHAT

