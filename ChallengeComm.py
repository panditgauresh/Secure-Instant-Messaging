import os
import hashlib

class ChallengeComm():
    def __init__(self):
        """
        The ChallengeComm class is used to generate challenges to prevent from a DOS attack. (Slow down client)
        """
        self.completed = 0
        self.no_of_challenges = 20000
        self.challenges = {}
        for i in range(0, self.no_of_challenges):
            self.challenges[i] = self.genRandomNumber(3)

    def getNextChallenge(self):
        """
        :return: Returns the next challenge with the index of the challenge for the client.
        """
        if(self.completed == self.no_of_challenges):
            self.completed = 0
        self.completed += 1
        return (self.challenges[self.completed-1],self.completed-1)

    def genRandomNumber(self, bit_size):
        """
        :param bit_size: The bit_size specifies the size of the random number which is returned.
        """
        return int(os.urandom(bit_size).encode('hex'),16)

    def refreshChallenge(self,index):
        """
        Refreshes the challenge by regenerating it at the given index
        :param index: the position of the challenge in the array
        """
        self.challenges[index] = self.genRandomNumber(3)

    def isChallengeMatched(self,mask,index,challenge):
        """
        :param mask: The mask is the size of the mask that has to be masked with the challenge
        :param index: Index is the index of the challenge in the array
        :param challenge: Challenge is the predicted value of the challenge
        :return: returns if the predicted challenge value matches the value in the challenge array at the index
        """
        print str(challenge)+":challenge:"+str(self.challenges[index])
        if (self.challenges[index] & ((1<<mask)-1)) == challenge:
            self.refreshChallenge(index)
            return True
        return False

    def computeChallenge(self, mask, hashed):
        """
        Computes the challenge given the mask size and the hashed value
        :param mask: size of the mask
        :param hashed: the received hash value
        :return: Returns the predicted challenge
        """
        print mask +": Mask Value" + str(hashed)
        for i in range((1<<int(mask))-1):
            if hashlib.sha256(str(i).encode('utf-8')).hexdigest() == hashed:
                return i
        return None