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

    def __init__(self, server_auth, user_addr_dict, addr_auths, request_cache, active_users):
        self.auth = server_auth
        self.user_addr_dict = user_addr_dict
        self.addr_auths = addr_auths
        self.request_cache = request_cache
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
            nonce = util.get_good_nonce(self.request_cache)
            res_msg = PacketOrganiser.prepare_packet(c.MSG_TYPE_LIST, nonce)
            util.add_to_request_cache(self.request_cache, nonce, c.MSG_TYPE_LIST,
                                      self.auth.dh_key, res_msg, self.auth.server_addr) # add to cache
            return c.MSG_TYPE_LIST, self.auth.server_addr, self.serv.sym_encrypt(self.auth.dh_key, res_msg)
        elif msg == c.USR_CMD_LOGOUT:
            # handle logout
            nonce = util.get_good_nonce(self.request_cache)
            res_msg = PacketOrganiser.prepare_packet(c.MSG_TYPE_LOGOUT, nonce)
            util.add_to_request_cache(self.request_cache, nonce, c.MSG_TYPE_LOGOUT,
                                      self.auth.dh_key, res_msg, self.auth.server_addr) # add to cache
            return c.MSG_TYPE_LOGOUT, self.auth.server_addr, self.serv.sym_encrypt(self.auth.dh_key, res_msg)
        elif match_res.group("chat") == c.USR_CMD_CHAT:
            username = match_res.group("username")
            chat_msg = match_res.group("msg")
            if username in self.user_addr_dict:
                # send the message to user
                addr = self.user_addr_dict[username]
                auth = self.addr_auths[addr]
                key = auth.dh_key
                nonce = util.get_good_nonce(self.request_cache)
                auth.last_nonce = nonce
                msg_to_send = PacketOrganiser.prepare_packet([c.MSG_TYPE_MSG, chat_msg, ""], nonce=nonce)
                encrypt_msg = self.serv.sym_encrypt(key, msg_to_send)
                msg = PacketOrganiser.add_sign(key, encrypt_msg)
                util.add_to_request_cache(self.request_cache, nonce, c.MSG_TYPE_MSG,
                                      key, msg_to_send, addr) # add to cache
                return None, addr, msg
            elif username in self.active_users:
                # start peer authentication
                nonce = util.get_good_nonce(self.request_cache)
                new_auth = ClientClientAuthentication(username, self.auth.crypto_service, chat_msg)
                new_auth.timestamp = PacketOrganiser.get_new_timestamp()  # timestamp when created, for packet resend
                key = self.auth.dh_key
                msg_to_send = PacketOrganiser.prepare_packet([c.MSG_TYPE_START_NEW_CHAT, username, ""], nonce=nonce)
                util.add_to_request_cache(self.request_cache, nonce, c.MSG_TYPE_START_NEW_CHAT,
                                      key, msg_to_send, self.auth.server_addr, new_auth) # add to cache
                return username, self.auth.server_addr, self.serv.sym_encrypt(key, msg_to_send)
            else:
                return None, None, c.ERR_CMD_NO_USER
        else:
            return None, None, c.ERR_CMD_CHAT

