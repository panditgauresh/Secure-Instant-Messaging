import os

class ChallengeComm():
	challenges
	completed
	def __init__(self):
		completed = 0
		no_of_challenges = 20000
		self.challenges = {}
		for i in range(0, no_of_challenges):
			self.challenges[i] = genRandomNumber(3)
	def getNextChallenge:
		if(self.completed == no_of_challenges)
			self.completed = 0
		self.completed += 1
		return (self.challenges[self.completed-1],self.completed-1)

	def genRandomNumber(self, bit_size):
                return int(os.urandom(bit_size).encode('hex'),16)

	def refreshChallenge(index):
		self.challenges[index] = genRandomNumber(3)

	def isChallengeMatched(mask,index,challenge):
		if((self.challenges[index] & mask) == challenge)
			refreshChallenge(index)
			return True
		return False
