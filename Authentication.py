import RequestAuthority
import time
from CryptoService import CryptoService
import Utilities as util


class Authentication():
    """
    Stages:
        0 : hello
        1 : hash challenge, df contribute
        2 : check the password hash
        3 : auth success
    """

    def __init__(self, addr, crypto_service):
        assert isinstance(crypto_service, CryptoService)
        self.crypto_service = crypto_service
        self.addr = addr
        self.timestamp = time.time()
        self.ra = RequestAuthority.RequestAuthority()
        self.stage = 0
        self.dh_secret = 0

    def get_response(self, message):
        pass

    def process_request(self,request):
        """
        Process request and generate the response
        :param request:
        :return:
        """
        if self.stage == 0:
            # sent a challenge to client
            c, ind, k = self.ra.getChallengeTupple()
            self.stage = 1
            return util.format_message(c, k, ind)
        elif self.stage == 1:
            # check the challenge answer, decrypt the client DH public key and send DH public key back
            c_ans, ind, enc_client_msg = request.split(',')
            c_ans = int(c_ans)
            ind = int(ind)
            k = self.ra.getMaskSize()  # TODO flaw when mask size changed
            if self.ra.challengeComm.isChallengeMatched(k, ind, c_ans) or True:  # TODO for testing
                dec_dh_pub_client, username, n1 = self.crypto_service.rsa_decrypt(enc_client_msg).split(",")  # TODO decryption, get N1, public key,
                print("Seen DH public key: {}, Username: {}, n1: {}".format(dec_dh_pub_client, username, n1))
                dh_pri_key = self.crypto_service.get_dh_pri_key()
                dh_pub_server = self.crypto_service.get_dh_pub_key(dh_pri_key)
                self.secret = self.crypto_service.get_dh_secret(dh_pri_key, dec_dh_pub_client)
                self.stage = 2
                # compose response: public key, K{N1, salt}, sign whole message
                salt = 0  # TODO get salt from username
                nonce_and_salt = util.format_message(n1, salt)
                enc_nonce_and_salt = self.crypto_service.sym_encrypt(self.secret, nonce_and_salt)
                msg = util.format_message(dh_pub_server, enc_nonce_and_salt)
                sign = self.crypto_service.rsa_sign(msg)
                signed_msg = util.format_message(msg, sign)
                return signed_msg
        elif self.stage == 2:
            # decrypt the message and check the password hash

            self.stage = 3
            pass


    def is_auth(self):
        print('Auth stage: {}'.format(self.stage))
        return self.stage == 3


