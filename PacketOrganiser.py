import datetime
import os
import re
import Consts as c
import hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class PacketOrganiser(object):
    def __init__(self):
        self.last_nonce = None

    def is_signature_match(dh_key, encrypt_msg, signature):
        #generate digest for the cipher text with HMAC
        h = hmac.HMAC(dh_key, hashes.SHA256(), backend=default_backend())
        h.update(encrypt_msg)
        sign = h.finalize()
        if sign == signature:
            return True
        return False

    @staticmethod
    def add_sign(dh_key, msg):
        #generate digest for the cipher text with HMAC
        h = hmac.HMAC(dh_key, hashes.SHA256(), backend=default_backend())
        h.update(msg)
        sign = h.finalize()
        return msg + sign

    @staticmethod
    def process_packet(pkt):
        """

        :param pkt:
        :return:
        """
        nonce = None
        ts = None
        msg_parts = []
        header = pkt[:c.HEADER_LEN]
        pkt = pkt[c.HEADER_LEN:]
        re_match = re.match(c.PKT_HEADER_RE, header)
        if re_match:
            has_nonce, has_ts, eofp, eosp = re_match.groups()
            eofp = int(eofp)
            eosp = int(eosp)
            if has_nonce == c.TRUE_STR:
                nonce = pkt[-c.NONCE_LEN:]
                pkt = pkt[:-c.NONCE_LEN]
            if has_ts == c.TRUE_STR:
                ts = pkt[-c.TS_LEN:]
                pkt = pkt[:-c.TS_LEN]
            msg_parts.append(pkt[:eofp])
            msg_parts.append(pkt[eofp:eosp])
            msg_parts.append(pkt[eosp:])
            if has_ts and not PacketOrganiser.isValidTimeStamp(ts):
                raise Exception("Timestamp invalid: {}".format(ts))
            return nonce, msg_parts
        else:
            raise Exception("Packet corrupted")

    @staticmethod
    def prepare_packet(msg_parts, nonce=None):
        """
        Add nonce, timestamp and header to the message
        :param msg_parts: no more than three msg parts can be handled
        :param nonce:
        :return:
        """
        if not isinstance(msg_parts, list):
            msg_parts = [msg_parts, "", ""]
        for ind, mp in enumerate(msg_parts):
            if not isinstance(mp, str):
                msg_parts[ind] = str(mp)
        has_ts = c.TRUE_STR
        has_nonce = c.TRUE_STR if nonce is not None else c.FALSE_STR
        eofp = str(len(msg_parts[0])).zfill(5)
        eosp = str(len(msg_parts[0] + msg_parts[1])).zfill(5)
        header = has_nonce + has_ts + eofp + eosp
        res_msg = header + "".join(msg_parts) + PacketOrganiser.get_new_timestamp() + (nonce if nonce is not None else "")
        return res_msg

    def getNonce(timestamp):
        return timestamp.rsplit(',', 1)[1]

    @staticmethod
    def genRandomNumber(byte_size=c.NONCE_LEN):
        """

        :param byte_size: sould be even number
        :return:
        """
        return os.urandom(byte_size / 2).encode('hex')

    @staticmethod
    def isValidTimeStamp(timestamp):
        recvTime = datetime.datetime.strptime(timestamp, "%m:%d:%Y:%H:%M:%S:%f")
        timeNow = datetime.datetime.now()
        diff = timeNow - recvTime
        print("ts: {}, now: {}, diff: {}".format(recvTime, timeNow, diff))
        if (diff.days == 0 and abs(diff) < datetime.timedelta(microseconds=300000)):
            return True
        return False

    def addNonce(self, out_msg):
        self.last_nonce = PacketOrganiser.genRandomNumber(c.NONCE_LEN)
        return str(out_msg) + "," + str(self.last_nonce)

    def verifyNonce(self, nonce):
        return self.last_nonce == nonce

    def addTimeStamp(self, out_msg):
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
        decrypt_msg = client_auth.crypto_service.sym_decrypt(client_auth.dh_key, encrypt_msg)
        #Todo: Change this method to remove nonce and timestamp in a better way
        msg, ts, nonce = decrypt_msg.rsplit(',')
        out_msg = self.addTimeStamp(msg)
        return client_auth.crypto_service.sym_encrypt(self.addNonce(out_msg))

    @staticmethod
    def get_new_timestamp():
        return datetime.datetime.now().strftime("%m:%d:%Y:%H:%M:%S:%f")

    def get_user_message(self, out_msg):
        chat, user, msg = out_msg.split()
        if(chat != c.USR_CMD_CHAT):
            return None, None

if __name__ == '__main__':
    pkt = "100000500008abcdeabcsomething12345678"
    n, ts, msg_ps = PacketOrganiser.process_packet(pkt)
    print(n, ts, msg_ps)

