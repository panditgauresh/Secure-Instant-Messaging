from multiprocessing.connection import answer_challenge
import ChallengeComm
import datetime
import hashlib

class RequestAuthority():
    def __init__(self):
        self.challengeComm = ChallengeComm.ChallengeComm()

    def getChallengeTupple(self):
        chalTup = self.challengeComm.getNextChallenge()
        masksize = self.getMaskSize()
        masked = chalTup[0] & ((1<<masksize)-1)
        hash_object = hashlib.sha256(str(masked).encode('utf-8')).hexdigest()
        return (hash_object, chalTup[1], masksize)

    def getMaskSize(self):
        return 17

    def compute_answer(self, chl, k):
        return self.challengeComm.computeChallenge(k,chl)