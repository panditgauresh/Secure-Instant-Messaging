"""
Handling the response/request from other parties.
* LIST
* Chatting msg from other client
"""

import Consts as c
import Utilities as util


class ClientChattingService(object):

    def __init__(self, ):
        pass

    def process_message(self, msg_parts, username=None):
        """
        process the message
        :param msg:
        :return:
        """
        type = msg_parts[0]
        res_to_print = None
        if type == c.MSG_TYPE_LIST:
            res_to_print = self.print_user_list(msg_parts[1])
        elif type == c.MSG_TYPE_MSG:
            res_to_print = self.parse_user_message(msg_parts[1], username)
        if res_to_print:
            util.cmd_output(res_to_print)


    def parse_user_message(self, msg, username):
        return '\r<-{}->:{}\n'.format(username, msg)


    def print_user_list(self, list_str):
        """

        :param list_str:
        :return:
        """
        users = list_str.split(",")
        return "\rOnline users:\n" + "\n".join(users) + "\n"
