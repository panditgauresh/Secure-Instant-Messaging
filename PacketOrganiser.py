import datetime
import os
import Consts as c

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

    def hasTimedOut(self,out_msg):
        timestamp = out_msg.rsplit(',',1)[1]
        recvTime = datetime.datetime.strptime(timestamp,"%m:%d:%Y:%H:%M:%S:%f")
        timeNow = datetime.datetime.now()
        diff = timeNow - recvTime
        if(diff.days == 0 and abs(diff) > datetime.timedelta(seconds=2)):
            return True
        return False

    def modifyTimeStamp(self, message, client_auth):
        encrypt_msg = message.rsplit(',',1)[0]
        decrypt_msg = client_auth.crypto_service.sym_decrypt(encrypt_msg)
        #Todo: Change this method to remove nonce and timestamp in a better way
        msg, ts, nonce = decrypt_msg.rsplit(',')
        out_msg = self.addTimeStamp(msg)
        return client_auth.crypto_service.sym_encrypt(self.addNonce(out_msg))

    def get_user_message(self, out_msg):
        chat, user, msg = out_msg.split()
        if(chat != c.USR_CMD_CHAT):
            return None, None