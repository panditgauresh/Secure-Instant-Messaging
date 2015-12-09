import RequestAuthority
import time
from CryptoService import CryptoService
import Utilities as util
import Consts as c
import socket
import sys
from PacketOrganiser import PacketOrganiser

class ClientClientAuthentication(object):
    """
    Stages:
        0 : hello
        1 : df contribute
        2 : new key established
    """

    def __init__(self, username, crypto_service, first_msg):
        assert isinstance(crypto_service, CryptoService)
        self.crypto_service = crypto_service
        self.timestamp = time.time()
        self.ra = RequestAuthority.RequestAuthority()
        self.stage = 0
        self.dh_key = 0
        self.server_addr = None
        self.auth_success = False
        self.packetgen = PacketOrganiser()
        self.first_msg = first_msg  # message initialize the C/C authentication
        self.last_nonce = None
        self.username = None

    def start_authenticate(self, sock, auth_info):
        """

        :param sock:
        :param auth_info: [b_addr, k_ab, ttb]
        :return:
        """
        # TODO to be continued
        print(auth_info)
        pass

    def handle_auth_request_from_client(self, sock):
        """
        handling Chatting requests from other client
        :param sock:
        :return:
        """
        pass

    def handle_auth_response_from_client(self, sock):
        """
        handle response message for auth between clients
        * TTB response from server

        :param sock:
        :return:
        """
        pass
