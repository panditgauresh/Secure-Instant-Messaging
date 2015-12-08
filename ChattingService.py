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

class ChattingService(object):

    def __init__(self, user_addr_dict, auth_dict):
        assert isinstance(user_addr_dict, dict)
        assert isinstance(auth_dict, dict)
        self.user_addr_dict = user_addr_dict
        self.auth_dict = auth_dict

    def get_response(self, addr, msg):
        # parse the msg
        msg_type, msg_args, ts, nonce = MessageParser.parse_message(msg)
        if tService.is_valid(ts):
            new_ts = tService.new_timestamp()
            self.auth_dict[addr].timestamp = new_ts  # update timestamp
            raw_msg = None
            if msg_type == c.MSG_TYPE_KEEP_ALIVE:
                raw_msg = self.handle_keep_alive()
            elif msg_type == c.MSG_TYPE_LIST:
                raw_msg = self.handle_list()
            elif msg_type == c.MSG_TYPE_START_NEW_CHAT:
                raw_msg = self.handle_start_new_chat(addr, msg_args)
            elif msg_type == c.MSG_TYPE_LOGOUT:
                raw_msg = self.handle_logout(addr)
            return util.format_message(raw_msg, new_ts, nonce) if raw_msg is not None else None
        else:
            return None

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
        b_addr, k_ab, ttb, n2, ts, n1
        :param a_addr:
        :param b_addr:
        :return:
        """
        k_ab = self.auth_dict[a_addr].crypto_service.new_sym_key()
        a_username = self.auth_dict[a_addr].username
        ttb = util.format_message(a_username, a_addr, k_ab, tService.new_timestamp())
        # TODO to be continued
        n2 = 2  # TODO generate nonce
        res = util.format_message(b_addr, k_ab, ttb, n2)
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




