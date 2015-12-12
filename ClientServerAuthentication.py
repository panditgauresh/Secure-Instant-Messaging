import RequestAuthority
import time
from CryptoService import CryptoService
import Utilities as util
import Consts as c
import socket
import sys
from PacketOrganiser import PacketOrganiser
import getpass

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
        This function authenticates the username and password with the server
        """
        # get username and password from user
        success = False
        while not success:
            self.username = util.get_user_input(c.USERNAME)
            password = util.get_user_input(c.PASSWORD)
            # password = getpass.getpass(c.PASSWORD)
            success = self._authenticate_with_server_helper(sock, self.username, password)
        print("Login success!")

    def _authenticate_with_server_helper(self, sock, username, password):
        """
        :param sock: The sock where the user has to be authenticated
        :param username: username of the user matched
        :param password: password of the user
        :return: Returns if the verification was successful or not
        """
        chl, k, ind = self._step_0_get_challenge(sock)
        salt = self._step_1_dh_key_establish(sock, chl, k, ind, username)
        if salt is None:
            return False
        is_success = self._step_2_password_verification(sock, password, salt)
        return is_success

    def _step_0_get_challenge(self, sock):
        """
        Challenge step.
        :param sock:
        :return:
        """
        # send greeting to the server
        # print("Get Username: {}, Password: {}".format(username, password))
        msg_to_send = PacketOrganiser.prepare_packet(c.GREETING, add_time=False)
        sock.sendto(msg_to_send, self.server_addr)
        recv_msg = util.get_one_response(sock, self.server_addr)
        # print("Receive msg from {}: {}".format(self.server_addr, recv_msg))
        _, recv_msg_parts = PacketOrganiser.process_packet(recv_msg)
        # chl, k, ind = recv_msg_parts
        return recv_msg_parts

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
        dh_pri_key = self.crypto_service.get_dh_pri_key()
        dh_pub_key = self.crypto_service.get_dh_pub_key(dh_pri_key)
        msg_to_send_parts = [dh_pub_key, username, ""]
        nonce = PacketOrganiser.genRandomNumber()
        msg_to_send = PacketOrganiser.prepare_packet(msg_to_send_parts, nonce=nonce, add_time=False)
        enc_msg_to_send = self.crypto_service.rsa_encrypt(msg_to_send)
        auth_1_msg_parts = [ans, ind, enc_msg_to_send]
        auth_1_msg = PacketOrganiser.prepare_packet(auth_1_msg_parts, add_time=False)
        sock.sendto(auth_1_msg, self.server_addr)

        recv_msg = util.get_one_response(sock, self.server_addr)
        # print("Receive msg from {}, length: {}".format(self.server_addr, len(recv_msg)))
        _, msg_sign = PacketOrganiser.process_packet(recv_msg)

        if msg_sign[0] == c.MSG_RESPONSE_WRONG_CR:
            print("Wrong username/password pair!")
            return
        else:
            msg, sign, _ = msg_sign
            if not self.crypto_service.rsa_verify(msg, sign):  # TODO for testing
                raise Exception("Step 1 signature verification fail.")
            _, pub_enc_salt = PacketOrganiser.process_packet(msg)
            other_pub_key, enc_salt, _ = pub_enc_salt
            other_pub_key = int(other_pub_key)
            self.dh_key = self.crypto_service.get_dh_secret(dh_pri_key, other_pub_key)
            dec_salt_pack = self.crypto_service.sym_decrypt(self.dh_key, enc_salt)
            n1, salt_parts = PacketOrganiser.process_packet(dec_salt_pack)
            salt = salt_parts[0]

            if n1 == nonce:
                return salt

    def _step_2_password_verification(self, sock, password, salt):
        """
        Verify password.
        :param sock:
        :param password:
        :param salt:
        :return:
        """
        pw_hash = self.crypto_service.compute_pw_hash(password, salt)
        nonce = PacketOrganiser.genRandomNumber()
        msg = PacketOrganiser.prepare_packet(pw_hash, nonce)
        auth_2_msg = self.crypto_service.sym_encrypt(self.dh_key, msg)
        sock.sendto(auth_2_msg, self.server_addr)
        # step 3
        recv_msg = util.get_one_response(sock, self.server_addr)
        # print("Receive msg from {}: {}".format(self.server_addr, recv_msg))
        dec_msg = self.crypto_service.sym_decrypt(self.dh_key, recv_msg)
        n, msg_parts = PacketOrganiser.process_packet(dec_msg)
        if n != nonce:
            raise Exception("Step 3 nonce failed.")
        auth_result = msg_parts[0]
        if auth_result == c.AUTH_SUCCESS:
            self.auth_success = True
        elif auth_result == c.MSG_RESPONSE_WRONG_CR:
            print("Wrong username/password pair!")
        return self.auth_success


    def is_auth(self):
        return self.auth_success

    def logout(self, sock):
        msg = PacketOrganiser.prepare_packet(c.MSG_TYPE_LOGOUT)
        enc_msg = self.crypto_service.sym_encrypt(self.dh_key, msg)
        sock.sendto(enc_msg, self.server_addr)