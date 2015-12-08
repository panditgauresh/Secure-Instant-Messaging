import datetime
import os

class PacketOrganiser(object):
    def __init__(self):
        self.last_nonce = None

    def getNonce(timestamp):
        return timestamp.rsplit(',',1)[1]

    def genRandomNumber(self, bit_size):
        return int(os.urandom(bit_size).encode('hex'),16)

    def isValidTimeStamp(self,timestamp):
        recvTime = datetime.datetime.strptime(timestamp,"%m:%d:%Y:%H:%M:%S:%f")
        timeNow = datetime.datetime.now()
        diff = timeNow - recvTime
        print("Date Difference")
        if(diff.days == 0 and abs(diff) < datetime.timedelta(microseconds=10000)):
            return True
        return False

    def addNonce(self,out_msg):
        self.last_nonce = self.genRandomNumber(8)
        return str(out_msg) + "," + str(self.last_nonce)

    def verifyNonce(self, nonce):
        if(int(self.last_nonce) == int(nonce)):
            return True
        return False

    def addTimeStamp(self,out_msg):
        return str(out_msg) + "," + datetime.datetime.now().strftime("%m:%d:%Y:%H:%M:%S:%f")