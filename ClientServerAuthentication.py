import RequestAuthority
import time
from CryptoService import CryptoService
import Utilities as util
import Consts as c
import socket
import sys
from PacketOrganiser import PacketOrganiser

class ClientServerAuthentication(object):
    """
    Stages:
        0 : hello
        1 : hash challenge, df contribute
        2 : check the password hash
        3 : auth success
    """

    def __init__(self, addr, remote_addr, crypto_service):
        assert isinstance(crypto_service, CryptoService)
        self.crypto_service = crypto_service
        self.addr = addr
        self.timestamp = time.time()
        self.ra = RequestAuthority.RequestAuthority()
        self.stage = 0
        self.dh_key = 0
        self.server_addr = remote_addr
        self.auth_success = False
        self.packetgen = PacketOrganiser()
        self.username = None

    def authenticate_with_server(self, sock):
        """

        :return:
        """
        # get username and password from user
        success = False
        while not success:
            self.username = util.get_user_input(c.USERNAME)
            password = util.get_user_input(c.PASSWORD)
            success = self._authenticate_with_server_helper(sock, self.username, password)
        print("Login success!")

    def _authenticate_with_server_helper(self, sock, username, password):
        """

        :param sock:
        :param username:
        :param password:
        :return:
        """
        chl, k, ind = self._step_0_get_challenge(sock)
        salt = self._step_1_dh_key_establish(sock, chl, k, ind, username)
        is_success = self._step_2_password_verification(sock, password, salt)
        return is_success

    def _step_0_get_challenge(self, sock):
        """
        Challenge step.
        :param sock:
        :return:
        """
        # TODO handle errors (i.e. wrong password, timestamp and nonce)
        # send greeting to the server
        # print("Get Username: {}, Password: {}".format(username, password))
        assert isinstance(sock, socket.socket)
        # if step == 0:
        sock.sendto(c.GREETING, self.server_addr)
        recv_msg = util.get_one_response(sock, self.server_addr)
        # print("Receive msg from {}: {}".format(self.server_addr, recv_msg))
        chl, k, ind = recv_msg.split(",")
        return chl, k, ind

    def _step_1_dh_key_establish(self, sock, chl, k, ind, username):
        """
        DH contribution exchange
        :param sock:
        :param chl:
        :param k:
        :param ind:
        :return:
        """
        ans = self.ra.compute_answer(chl, k)
        print("challenge:"+str(chl))
        print("challenge:"+str(ans))
        dh_pri_key = self.crypto_service.get_dh_pri_key()
        dh_pub_key = self.crypto_service.get_dh_pub_key(dh_pri_key)
        msg = util.format_message(dh_pub_key, username)
        nonce_msg = self.packetgen.addNonce(msg)
        enc_msg = self.crypto_service.rsa_encrypt(nonce_msg)
        auth_1_msg = util.format_message(ans, ind, enc_msg)
        sock.sendto(auth_1_msg, self.server_addr)
        # step 2
        recv_msg = util.get_one_response(sock, self.server_addr)
        # print("Receive msg from {}, length: {}".format(self.server_addr, len(recv_msg)))
        rr = recv_msg.split(",")
        other_pub_key = rr[0]
        enc_n1_and_salt = recv_msg[(len(other_pub_key) + 1):-513]
        sign = recv_msg[-512]

        msg_body = other_pub_key + "," + enc_n1_and_salt
        if self.crypto_service.rsa_verify(msg_body, sign) or True:  # TODO for testing
            other_pub_key = int(other_pub_key)
            self.dh_key = self.crypto_service.get_dh_secret(dh_pri_key, other_pub_key)
            n1_res, salt = self.crypto_service.sym_decrypt(self.dh_key, enc_n1_and_salt).split(",")
            if self.packetgen.verifyNonce(n1_res):
                # calculate password
                return salt
        return None

    def _step_2_password_verification(self, sock, password, salt):
        """
        Verify password.
        :param sock:
        :param password:
        :param salt:
        :return:
        """
        pw_hash = self.crypto_service.compute_pw_hash(password, salt)
        pw_hash_timestamp = self.packetgen.addTimeStamp(pw_hash)
        pw_hash_msg = self.packetgen.addNonce(pw_hash_timestamp)
        msg = util.format_message(pw_hash_msg)
        auth_2_msg = self.crypto_service.sym_encrypt(self.dh_key, msg)
        sock.sendto(auth_2_msg, self.server_addr)
        # step 3
        recv_msg = util.get_one_response(sock, self.server_addr)
        # print("Receive msg from {}: {}".format(self.server_addr, recv_msg))
        auth_result, n2_res = self.crypto_service.sym_decrypt(self.dh_key, recv_msg).split(",")
        if self.packetgen.verifyNonce(n2_res):
            if auth_result == c.AUTH_SUCCESS:
                self.auth_success = True
            elif auth_result == c.MSG_RESPONSE_WRONG_PW:
                print("Wrong username/password pair!")
        return self.auth_success


    def is_auth(self):
        return self.auth_success

    def logout(self, sock):
        msg = PacketOrganiser.prepare_packet(c.MSG_TYPE_LOGOUT)
        enc_msg = self.crypto_service.sym_encrypt(self.dh_key, msg)
        sock.sendto(enc_msg, self.server_addr)