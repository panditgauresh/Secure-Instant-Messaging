import RequestAuthority
import time
from CryptoService import CryptoService
import Utilities as util
import Consts as c
import socket
import sys
import PacketOrganiser

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
        self.packetgen = PacketOrganiser.PacketOrganiser()
        self.username = None

    def start_authenticate(self, sock):
        """

        :return:
        """
        # get username and password from user
        username = util.get_user_input(c.USERNAME)
        password = util.get_user_input(c.PASSWORD)
        self.username = username
        # username = "admin"
        # password = "admin123"
        success = False
        while not success:
            success, msg = self._establish_server_session_key(sock, username, password)
            if msg == c.WRONG_PASSWORD:
                password = util.get_user_input(c.PASSWORD)
        print("Login success!")


    def _establish_server_session_key(self, sock, username, password):
        # TODO handle errors (i.e. wrong password, timestamp and nonce)
        # send greeting to the server
        # print("Get Username: {}, Password: {}".format(username, password))
        assert isinstance(sock, socket.socket)
        sock.sendto(c.GREETING, self.server_addr)
        recv_msg = util.get_one_response(sock, self.server_addr)
        # print("Receive msg from {}: {}".format(self.server_addr, recv_msg))
        chl, k, ind = recv_msg.split(",")
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
                # calculate password hash
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
                    if auth_result == c.SUCCESS:
                        self.auth_success = True
                else:
                    print("N2 fail")
            else:
                print("N1 fail")
        else:
            print("Sign verification failed.")
        return self.auth_success, c.SUCCESS

    def get_response(self, message):
        pass

    def is_auth(self):
        return self.auth_success
