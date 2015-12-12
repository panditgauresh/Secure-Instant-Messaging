import RequestAuthority
import time
from CryptoService import CryptoService
import Utilities as util
import Consts as c
from PacketOrganiser import PacketOrganiser
import datetime

class Authentication(object):
    """

    """

    def __init__(self, addr, crypto_service, pw_dict):
        """

        :param addr: the IP and port as a tupple of the client
        :param crypto_service: CryptoService to handle encryption and decryption
        :param pw_dict: a reference to the username/password dictionary
        :return:
        """
        assert isinstance(crypto_service, CryptoService)
        self.crypto_service = crypto_service
        self.addr = addr
        self.timestamp = datetime.datetime.now().strftime("%m:%d:%Y:%H:%M:%S:%f")
        self.ra = RequestAuthority.RequestAuthority()
        self.stage = 0
        self.dh_key = 0
        self.username = ""
        self.pw_dict = pw_dict
        self.masksize = 0
        self.loginfailures = 0

    def process_request(self, request, user_addr_dict):
        """
        Process request and generate the response
        Stages:
        0 : hello
        1 : hash challenge, df contribute
        2 : check the password hash
        3 : auth success
        :param request: request from client
        :return:
        """
        if self.stage == 0:
            return self._stage_0_generate_challenge()
        elif self.stage == 1:
            return self._stage_1_dh_key_exchange(request, user_addr_dict)
        elif self.stage == 2:
            return self._stage_2_pw_check(request, user_addr_dict)

    def _stage_0_generate_challenge(self):
        """
        Generate and send challenge to client
        :return:
        """
        # sent a challenge to client
        chl, ind, self.masksize = self.ra.get_challenge_tupple(self.loginfailures)
        self.stage = 1
        msg_to_send_parts = [chl, self.masksize, ind]
        msg_to_send = PacketOrganiser.prepare_packet(msg_to_send_parts, add_time=False)
        return msg_to_send

    def _stage_1_dh_key_exchange(self, request, user_addr_dict):
        """
        check the challenge answer, decrypt the client DH public key and send DH public key back
        :param request: request from client
        :param user_addr_dict: dictionary which keep tracking of the username and corresponding IP address and port
        :return:
        """
        try:
            _, request_parts = PacketOrganiser.process_packet(request)
            c_ans, ind, enc_client_msg = request_parts
        except:
            return None
        c_ans = int(c_ans)
        ind = int(ind)
        #k = self.ra.getMaskSize()  # TODO flaw when mask size changed
        if self.ra.challengeComm.isChallengeMatched(self.masksize, ind, c_ans):
            dec_msg = self.crypto_service.rsa_decrypt(enc_client_msg)
            n1, dec_msg_parts = PacketOrganiser.process_packet(dec_msg)
            dec_dh_pub_client, username, _ = dec_msg_parts
            if username in user_addr_dict:  # prevent duplicate login
                return None

            if username not in self.pw_dict:
                self.stage = 0
                return PacketOrganiser.prepare_packet(c.MSG_RESPONSE_WRONG_CR, nonce=n1)
            else:
                self.username = username
                dec_dh_pub_client = int(dec_dh_pub_client)
                dh_pri_key = self.crypto_service.get_dh_pri_key()
                dh_pub_server = self.crypto_service.get_dh_pub_key(dh_pri_key)
                self.dh_key = self.crypto_service.get_dh_secret(dh_pri_key, dec_dh_pub_client)
                # compose response: public key, K{N1, salt}, sign whole message
                salt = self.pw_dict[self.username][1]  # get salt from username
                salt_pack = PacketOrganiser.prepare_packet(salt, nonce=n1, add_time=False)
                enc_salt = self.crypto_service.sym_encrypt(self.dh_key, salt_pack)
                msg = PacketOrganiser.prepare_packet([dh_pub_server, enc_salt, ""], add_time=False)
                sign = self.crypto_service.rsa_sign(msg)

                signed_msg = PacketOrganiser.prepare_packet([msg, sign, ""], add_time=False)
                self.stage = 2
                return signed_msg

    def _stage_2_pw_check(self, request, user_addr_dict):
        """
        Stage 2 is to check if the password is correct
        :param request: Request is the incoming message which contains the password.
        :param user_addr_dict: The user_add_dict is the dictionary which has each user and associated address stored.
        :return: The method returns a encrypted response message
        """
        # decrypt the message and check the password hash
        dec_request = self.crypto_service.sym_decrypt(self.dh_key, request)
        n, request_parts = PacketOrganiser.process_packet(dec_request)
        pw_hash = request_parts[0]
        if pw_hash != self.pw_dict[self.username][0]:
            msg = PacketOrganiser.prepare_packet(c.MSG_RESPONSE_WRONG_PW, nonce=n)
            enc_msg = self.crypto_service.sym_encrypt(self.dh_key, msg)
            self.stage = 0
            self.loginfailures += 1
        else:
            msg = PacketOrganiser.prepare_packet(c.AUTH_SUCCESS, nonce=n)
            enc_msg = self.crypto_service.sym_encrypt(self.dh_key, msg)
            self.stage = 3
            user_addr_dict[self.username] = self.addr
        return enc_msg


    def is_auth(self):
        """
        :return: If Authentication is complete the stage is 3
        """
        return self.stage == 3
