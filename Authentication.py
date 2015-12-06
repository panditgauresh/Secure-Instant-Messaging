import RequestAuthority
import time
from CryptoService import CryptoService



class Authentication():
    """
    Stages:
        0 : hello
        1 : hash challenge, df contribute
        2 : check the password hash
        3 : auth success
    """

    def __init__(self, addr, p, g, cryto_service):
        assert isinstance(cryto_service, CryptoService)
        self.cryto_service = cryto_service
        self.addr = addr
        self.timestamp = time.time()
        self.ra = RequestAuthority.RequestAuthority()
        self.stage = 0
        self.dh_pri_key = 0
        self.dh_secret = 0

    def get_response(self, message):
        pass

    def process_request(self,request):
        if self.stage == 0:
            # sent a challenge to client
            c, ind, k = self.ra.getChallengeTupple()
            self.stage = 1
            return "{},{},{}".format(c, k, ind)
        elif self.stage == 1:
            # check the challenge answer, decrypt the client DH public key and send DH public key back
            c_ans, ind, enc_client_msg = request.split(',')
            c_ans = int(c_ans)
            ind = int(ind)
            k = self.ra.getMaskSize()  # TODO flaw when mask size changed
            if self.ra.challengeComm.isChallengeMatched(k, ind, c_ans) or True:  # TODO for testing
                dec_dh_pub_client, addr, n1 = self.cryto_service.rsa_decrypt(enc_client_msg).split(",")  # TODO decryption, get N1, public key, and verify addr,
                print("Seen DH public key: {}, Address: {}, n1: {}".format(dec_dh_pub_client, addr, n1))
                if addr == "{}:{}".format(self.addr[0], self.addr[1]) and False: # TODO for testing
                    self.dh_pri_key = self.cryto_service.get_dh_pri_key()
                    dh_pub_server = self.cryto_service.get_dh_pub_key(self.dh_pri_key)
                    secret = self.cryto_service.get_dh_secret(self.dh_pri_key, dec_dh_pub_client)
                    # compose response: public key, K{N1, salt}, sign whole message
                    self.stage = 2
                    return "{}, {}, salt, sign whole message".format(dh_pub_server, n1)
        elif self.stage == 2:
            # decrypt the message and check the password hash

            self.stage = 3
            pass


    def is_auth(self):
        print('Auth stage: {}'.format(self.stage))
        return self.stage == 3


