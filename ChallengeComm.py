import os
import hashlib

class ChallengeComm():
    def __init__(self):
        self.completed = 0
        self.no_of_challenges = 20000
        self.challenges = {}
        for i in range(0, self.no_of_challenges):
            self.challenges[i] = self.genRandomNumber(3)
    def getNextChallenge(self):
        if(self.completed == self.no_of_challenges):
            self.completed = 0
        self.completed += 1
        return (self.challenges[self.completed-1],self.completed-1)

    def genRandomNumber(self, bit_size):
                return int(os.urandom(bit_size).encode('hex'),16)

    def refreshChallenge(self,index):
        self.challenges[index] = self.genRandomNumber(3)

    def isChallengeMatched(self,mask,index,challenge):
        print str(challenge)+":challenge:"+str(self.challenges[index])
        if (self.challenges[index] & ((1<<mask)-1)) == challenge:
            self.refreshChallenge(index)
            return True
        return False

    def computeChallenge(self, mask, hashed):
        print mask +": Mask Value" + str(hashed)
        for i in range((1<<int(mask))-1):
            if hashlib.sha256(str(i).encode('utf-8')).hexdigest() == hashed:
                return i
        return None