from RequestAuthority import RequestAuthority
import time
from CryptoService import CryptoService
import Utilities as util
import Consts as c
from PacketOrganiser import PacketOrganiser

class ClientClientAuthentication(object):
    """
    Stages:
        0 : hello
        1 : df contribute
        2 : new key established
    """

    def __init__(self, username, crypto_service, first_msg=None):
        assert isinstance(crypto_service, CryptoService)
        self.crypto_service = crypto_service
        self.timestamp = time.time()
        self.ra = RequestAuthority()
        self.stage = 0
        self.dh_key = 0
        self.pri_key = 0
        self.auth_success = False
        self.packetgen = PacketOrganiser()
        self.first_msg = first_msg  # message initialize the C/C authentication
        self.last_nonce = None
        self.username = username

    def complete_auth(self):
        return self.auth_success

    def start_authenticate(self, sock, auth_info, a_username):
        """

        :param sock:
        :param auth_info: [b_addr, k_ab, ttb]
        :return:
        """
        b_addr = util.str_to_addr(auth_info[0])
        k_ab = auth_info[1]
        ttb = auth_info[2]

        # ttb, k_ab{a, pub_key, ts}
        self.pri_key = self.crypto_service.get_dh_pri_key()
        self.dh_key = k_ab
        pub_key = self.crypto_service.get_dh_pub_key(self.pri_key)
        inside_msg_parts = [a_username, pub_key, ""]
        inside_msg = PacketOrganiser.prepare_packet(inside_msg_parts)
        enc_inside_msg = self.crypto_service.sym_encrypt(k_ab, inside_msg)

        msg_parts = [ttb, enc_inside_msg, ""]
        pack_to_send = PacketOrganiser.prepare_packet(msg_parts)
        # send the hello message to the other client
        sock.sendto(pack_to_send, b_addr)
        return b_addr

    def handle_auth_request_from_client(self, sock, server_dh_key, nonce):
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
