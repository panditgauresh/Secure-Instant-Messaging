import os

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
        if((self.challenges[index] & mask) == challenge):
            self.refreshChallenge(index)
            return True
        return False
