import datetime
import os
import re
import Consts as c


class PacketOrganiser(object):
    def __init__(self):
        self.last_nonce = None

    @staticmethod
    def divide_signature(msg):
        return msg[:-c.HMAC_LEN], msg[-c.HMAC_LEN:]

    @staticmethod
    def process_packet(pkt):
        """
        packet struct: header, msg, nonce, timestamp
        header: has_ts(1), has_nonce(1), end of first part(5), end of second part(5)
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
            has_ts, has_nonce, eofp, eosp = re_match.groups()
            eofp = int(eofp)
            eosp = int(eosp)
            if has_ts == c.TRUE_STR:
                ts = pkt[-c.TS_LEN:]
                pkt = pkt[:-c.TS_LEN]
            if has_nonce == c.TRUE_STR:
                nonce = pkt[-c.NONCE_LEN:]
                pkt = pkt[:-c.NONCE_LEN]
            msg_parts.append(pkt[:eofp])
            msg_parts.append(pkt[eofp:eosp])
            msg_parts.append(pkt[eosp:])
            if has_ts == c.TRUE_STR and not PacketOrganiser.isValidTimeStamp(ts):
                raise Exception("Timestamp invalid: {}".format(ts))
            return nonce, msg_parts
        else:
            raise Exception("Packet corrupted")

    @staticmethod
    def prepare_packet(msg_parts, nonce=None, add_time=True):
        """
        Add nonce, timestamp and header to the message
        packet struct: header, msg, nonce, timestamp
        header: has_ts(1), has_nonce(1), end of first part(5), end of second part(5)
        :param msg_parts: no more than three msg parts can be handled
        :param nonce:
        :return:
        """
        if not isinstance(msg_parts, list):
            msg_parts = [msg_parts, "", ""]
        else:
            while len(msg_parts) < 3:
                msg_parts.append("")
        for ind, mp in enumerate(msg_parts):
            if not isinstance(mp, str):
                msg_parts[ind] = str(mp)
        has_ts = c.TRUE_STR if add_time else c.FALSE_STR
        has_nonce = c.TRUE_STR if nonce is not None else c.FALSE_STR
        eofp = str(len(msg_parts[0])).zfill(5)
        eosp = str(len(msg_parts[0] + msg_parts[1])).zfill(5)
        header = has_ts + has_nonce + eofp + eosp
        res_msg = header + "".join(msg_parts) + (nonce if nonce is not None else "")
        res_msg += PacketOrganiser.get_new_timestamp() if add_time else ""
        return res_msg


    @staticmethod
    def genRandomNumber(byte_size=c.NONCE_LEN):
        """

        :param byte_size: sould be even number
        :return:
        """
        return os.urandom(byte_size / 2).encode('hex')

    @staticmethod
    def isValidTimeStamp(timestamp, micro_s=300000):
        """
        :param timestamp: The timestamp to be verified for validity
        :param micro_s: The number of microseconds to be verified agains
        :return: returns true if the timestamp is withing micro_s microseconds from current time, else false
        """
        diff = PacketOrganiser.get_time_diff_from_now(timestamp)
        # print("ts: {}, now: {}, diff: {}".format(recvTime, timeNow, diff))
        if (diff.days == 0 and abs(diff) < datetime.timedelta(microseconds=micro_s)):
            return True
        return False

    @staticmethod
    def isValidTimeStampSeconds(timestamp, sec=60):
        """
        :param timestamp: The timestamp to be verified for validity
        :param micro_s: The number of seconds to be verified agains
        :return: returns true if the timestamp is withing sec seconds from current time, else false
        """
        diff = PacketOrganiser.get_time_diff_from_now(timestamp)
        # print("ts: {}, now: {}, diff: {}".format(recvTime, timeNow, diff))
        if (diff.days == 0 and abs(diff) < datetime.timedelta(seconds=sec)):
            return True
        return False

    @staticmethod
    def get_time_diff_from_now(timestamp):
        """
        :param timestamp: the requested timestamp
        :return: Returns the absolute difference as a datetime object
        """
        recvTime = datetime.datetime.strptime(timestamp, "%m:%d:%Y:%H:%M:%S:%f")
        timeNow = datetime.datetime.now()
        return timeNow - recvTime

    def addNonce(self, out_msg):
        """
        :param out_msg: The message to which nonce has to be added
        :return: Appends nonce and sends the message
        """
        self.last_nonce = PacketOrganiser.genRandomNumber(c.NONCE_LEN)
        return str(out_msg) + "," + str(self.last_nonce)

    def verifyNonce(self, nonce):
        """
        :param nonce: The function is used to verify nonce.
        :return: returns true if it matches else false
        """
        return self.last_nonce == nonce

    def addTimeStamp(self, out_msg):
        """
        :param out_msg: The message to which timestamp is to be added
        :return: timestamp appended message
        """
        return str(out_msg) + "," + datetime.datetime.now().strftime("%m:%d:%Y:%H:%M:%S:%f")

    def hasTimedOut(self,out_msg):
        """
        :param out_msg:
        :return: To check if the current message has been timed out.
        """
        timestamp = out_msg.rsplit(',',1)[1]
        recvTime = datetime.datetime.strptime(timestamp,"%m:%d:%Y:%H:%M:%S:%f")
        timeNow = datetime.datetime.now()
        diff = timeNow - recvTime
        if(diff.days == 0 and abs(diff) > datetime.timedelta(seconds=2)):
            return True
        return False

    def modifyTimeStamp(self, message, client_auth):
        """
        :param message: message containing timestamp
        :param client_auth: the auth of the client used to encrypt and decrypt the message
        :return: Returns the message with modified timestamp
        """
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
        """
        :param out_msg:
        :return: returns none if the chat message doesnt match
        """
        chat, user, msg = out_msg.split()
        if(chat != c.USR_CMD_CHAT):
            return None, None

if __name__ == '__main__':
    pkt = "100000500008abcdeabcsomething12345678"
    n, ts, msg_ps = PacketOrganiser.process_packet(pkt)
    print(n, ts, msg_ps)

