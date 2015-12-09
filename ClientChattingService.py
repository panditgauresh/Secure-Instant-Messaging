"""
Handling the response/request from other parties.
* LIST
* Chatting msg from other client
"""

import Consts as c
import Utilities as util


class ClientChattingService(object):

    def __init__(self, active_users):
        assert isinstance(active_users, list)
        self.active_users = active_users

    def process_message(self, msg_parts, username=None):
        """
        process the message
        :param msg:
        :return:
        """
        type = msg_parts[0]
        res_to_print = None
        if type == c.MSG_TYPE_LIST:
            self.active_users.append(msg_parts[1])
            res_to_print = self.process_user_list(msg_parts[1])
        elif type == c.MSG_TYPE_MSG:
            res_to_print = self.parse_user_message(msg_parts[1], username)
        if res_to_print:
            util.cmd_output(res_to_print)


    def parse_user_message(self, msg, username):
        """
        Need to send ack!
        :param msg:
        :param username:
        :return:
        """
        return '\r<-{}->:{}\n'.format(username, msg)


    def process_user_list(self, list_str):
        """

        :param list_str:
        :return:
        """
        users = list_str.split(",")
        self.active_users = list(users)
        return "\rOnline users:\n" + "\n".join(users) + "\n"
