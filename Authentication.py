import RequestAuthority
import time
from CryptoService import CryptoService
import Utilities as util
import Consts as c
from PacketOrganiser import PacketOrganiser
import datetime

class Authentication(object):
    """
    Stages:
        0 : hello
        1 : hash challenge, df contribute
        2 : check the password hash
        3 : auth success
    """

    def __init__(self, addr, crypto_service, pw_dict):
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

    def process_request(self, request, user_addr_dict):
        """
        Process request and generate the response
        :param request:
        :return:
        """
        # print("Request received from {}: {}".format(self.addr, request))
        if self.stage == 0:
            return self._stage_0_generate_challenge()
        elif self.stage == 1:
            return self._stage_1_dh_key_exchange(request, user_addr_dict)
        elif self.stage == 2:
            return self._stage_2_pw_check(request, user_addr_dict)

    def _stage_0_generate_challenge(self):
        # sent a challenge to client
        chl, ind, self.masksize = self.ra.get_challenge_tupple()
        self.stage = 1
        # msg_to_send = PacketOrganiser.prepare_packet()

        return util.format_message(chl, self.masksize, ind)

    def _stage_1_dh_key_exchange(self, request, user_addr_dict):
        # check the challenge answer, decrypt the client DH public key and send DH public key back
        try:
            rr = request.split(',')
            c_ans = rr[0]
            ind = rr[1]
            enc_client_msg = request[(len(c_ans + ind) + 2):]
        except:
            return None
        c_ans = int(c_ans)
        ind = int(ind)
        #k = self.ra.getMaskSize()  # TODO flaw when mask size changed
        if self.ra.challengeComm.isChallengeMatched(self.masksize, ind, c_ans):  # TODO for testing
            dec_msg = self.crypto_service.rsa_decrypt(enc_client_msg)
            dec_dh_pub_client, username, n1 = dec_msg.split(",")  # TODO decryption, get N1, public key,
            if username in user_addr_dict:  # prevent duplicate login
                return None
            self.username = username
            dec_dh_pub_client = int(dec_dh_pub_client)
            # print("Seen DH public key: {}, Username: {}, n1: {}".format(dec_dh_pub_client, self.username, n1))
            dh_pri_key = self.crypto_service.get_dh_pri_key()
            dh_pub_server = self.crypto_service.get_dh_pub_key(dh_pri_key)
            self.dh_key = self.crypto_service.get_dh_secret(dh_pri_key, dec_dh_pub_client)
            # print("DH key established: {}".format(self.dh_key))
            # compose response: public key, K{N1, salt}, sign whole message
            salt = self.pw_dict[self.username][1]  # TODO get salt from username
            nonce_and_salt = util.format_message(n1, salt)
            enc_nonce_and_salt = self.crypto_service.sym_encrypt(self.dh_key, nonce_and_salt)
            msg = util.format_message(dh_pub_server, enc_nonce_and_salt)
            sign = self.crypto_service.rsa_sign(msg)
            signed_msg = util.format_message(msg, sign)
            self.stage = 2
            return signed_msg

    def _stage_2_pw_check(self, request, user_addr_dict):
        # decrypt the message and check the password hash
        pw_hash, timestamp, n = self.crypto_service.sym_decrypt(self.dh_key, request).split(',')
        if PacketOrganiser.isValidTimeStamp(timestamp):
            if pw_hash != self.pw_dict[self.username][0]:
                msg = util.format_message(c.MSG_RESPONSE_WRONG_PW, n)
                enc_msg = self.crypto_service.sym_encrypt(self.dh_key, msg)
                self.stage = 0
            else:
                msg = util.format_message(c.AUTH_SUCCESS, n)
                enc_msg = self.crypto_service.sym_encrypt(self.dh_key, msg)
                self.stage = 3
                user_addr_dict[self.username] = self.addr
                # print("Authentication success.")
            return enc_msg
        else:
            print("TimeStamp Incorrect: {}".format(timestamp))

    def is_auth(self):
        # print('Auth stage: {}'.format(self.stage))
        return self.stage == 3
