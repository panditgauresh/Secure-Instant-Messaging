import RequestAuthority
import time
import DH



class Authentication():
    """
    Stages:
        0 : hello
        1 : hash challenge, df contribute
        2 : shared secret challenge
        3 : auth success
    """

    def __init__(self, addr, p, g):
        self.addr = addr
        self.timestamp = time.strptime(time.time(),"%H:%M:%S:%f")
        self.dh = DH.DiffieHellman(p, g)
        self.ra = RequestAuthority.RequestAuthority()
        self.stage = 0

    def get_response(self, message):
        pass

    def process_request(self,request):
        pass

    def is_auth(self):
        return self.stage == 3


