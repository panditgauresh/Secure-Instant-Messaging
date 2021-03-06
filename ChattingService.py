"""
Handling requests after authentication phase.
* Keep-alive
* List
* Start chatting
* Logout
"""

import Consts as c
import Utilities as util
from PacketOrganiser import PacketOrganiser
from CryptoService import CryptoService
import datetime

class ChattingService(object):

    def __init__(self, user_addr_dict, auth_dict, crypto_service):
        assert isinstance(user_addr_dict, dict)
        assert isinstance(auth_dict, dict)
        assert isinstance(crypto_service, CryptoService)

        self.user_addr_dict = user_addr_dict
        self.auth_dict = auth_dict
        self.crypto_service = crypto_service

    def get_response(self, addr, msg_parts):
        """
        :param addr: The address of the client requesting the response
        :param msg_parts: The request message in parts.
        :return: Returns the value of the response for every type of request of message
        """
        # parse the msg
        res_msg = None
        msg_type = msg_parts[0]
        if msg_type == c.MSG_TYPE_KEEP_ALIVE:
            res_msg = self.handle_keep_alive(addr)
        elif msg_type == c.MSG_TYPE_LIST:
            res_msg = self.handle_list()
        elif msg_type == c.MSG_TYPE_START_NEW_CHAT:
            b_username = msg_parts[1]
            res_msg = self.handle_start_new_chat(addr, b_username)
        elif msg_type == c.MSG_TYPE_LOGOUT:
            res_msg = self.handle_logout(addr)
        return res_msg

    def handle_keep_alive(self, addr):
        """
        :return: updates the timestamp of the client and sends a OK response.
        """
        auth = self.auth_dict[addr]
        auth.timestamp = datetime.datetime.now().strftime("%m:%d:%Y:%H:%M:%S:%f")
        return c.MSG_RESPONSE_OK

    def handle_list(self):
        """
        :return: Handles the list input and sends the list of active users as response.
        """
        res = ""
        for user, addr in self.user_addr_dict.iteritems():
            auth = self.auth_dict[addr]
            if not PacketOrganiser.isValidTimeStampSeconds(auth.timestamp,c.KEEP_ALIVE_TIME):
                self.auth_dict.pop(addr)
                continue
            res += user + ","
        return [c.MSG_TYPE_LIST, res[:-1], ""]

    def handle_start_new_chat(self, a_addr, b_username):
        """
        b_addr, k_ab, ttb, ts, n1
        :param a_addr: Chat requesting client address
        :param b_addr: Address of client wanting to chat with
        :return: The server sends as response the ticket to b and a symettric key to talk to b.
        """
        k_ab = self.auth_dict[a_addr].crypto_service.new_sym_key()
        a_username = self.auth_dict[a_addr].username
        b_addr = self.user_addr_dict[b_username]
        auth = self.auth_dict[b_addr]
        if not PacketOrganiser.isValidTimeStampSeconds(auth.timestamp,c.KEEP_ALIVE_TIME):
            self.auth_dict.pop(b_addr)
            return c.ERR_CLIENT_DOWN
        k_b = self.auth_dict[b_addr].dh_key
        ttb = PacketOrganiser.prepare_packet([a_username, util.addr_to_str(a_addr), k_ab])
        enc_ttb = self.crypto_service.sym_encrypt(k_b, ttb)
        signed_enc_ttb = enc_ttb + self.crypto_service.rsa_sign(enc_ttb)
        return [util.addr_to_str(b_addr), k_ab, signed_enc_ttb]

    def handle_logout(self, addr):
        """
        :param addr: addr of the client requesting logout
        :return: responds with an OK message
        """
        username = self.auth_dict[addr].username
        self.user_addr_dict.pop(username)
        self.auth_dict.pop(addr)
        return c.MSG_RESPONSE_OK




