"""
Handling requests after authentication phase.
* Keep-alive
* List
* Start chatting
* Logout
"""

from MessageParser import MessageParser
import Consts as c
from TimestampService import TimestampService as tService
import Utilities as util
from PacketOrganiser import PacketOrganiser

class ChattingService(object):

    def __init__(self, user_addr_dict, auth_dict):
        assert isinstance(user_addr_dict, dict)
        assert isinstance(auth_dict, dict)
        self.user_addr_dict = user_addr_dict
        self.auth_dict = auth_dict

    def get_response(self, addr, msg_parts):
        # parse the msg
        print(addr)
        print(msg_parts)
        res_msg = None
        msg_type = msg_parts[0]
        if msg_type == c.MSG_TYPE_KEEP_ALIVE:
            res_msg = self.handle_keep_alive()
        elif msg_type == c.MSG_TYPE_LIST:
            res_msg = self.handle_list()
        elif msg_type == c.MSG_TYPE_START_NEW_CHAT:
            res_msg = self.handle_start_new_chat(addr, msg_args)
        elif msg_type == c.MSG_TYPE_LOGOUT:
            res_msg = self.handle_logout(addr)
        return res_msg

    def handle_keep_alive(self):
        """

        :return:
        """
        return c.MSG_RESPONSE_OK

    def handle_list(self):
        """

        :return:
        """
        res = ""
        for user in self.user_addr_dict:
            res += user + ","
        return res[:-1]

    def handle_start_new_chat(self, a_addr, b_addr):
        """
        b_addr, k_ab, ttb, ts, n1
        :param a_addr:
        :param b_addr:
        :return:
        """
        k_ab = self.auth_dict[a_addr].crypto_service.new_sym_key()
        a_username = self.auth_dict[a_addr].username
        ttb = PacketOrganiser.prepare_packet([a_username, util.addr_to_str(a_addr), k_ab])
        # TODO to be continued
        res = util.format_message(b_addr, k_ab, ttb)
        return res

    def handle_logout(self, addr):
        """

        :param addr:
        :return:
        """
        username = self.auth_dict[addr].username
        self.user_addr_dict.pop(username)
        self.auth_dict.pop(addr)
        return c.MSG_RESPONSE_OK




