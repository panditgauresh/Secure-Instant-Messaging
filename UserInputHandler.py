"""
Handle the user input including LIST, send message to someone
"""

import re
import Consts as c


class UserInputHandler(object):

    def __init__(self):
        pass

    def handle_input(self, msg):
        """

        :param input:
        :return:
        """
        # LIST, CHAT
        match_res = re.match(c.USR_CMD_RE, msg)
        if match_res:



        pass


