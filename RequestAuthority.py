import ChallengeComm

class RequestAuthority():
	def __init__(self):
		self.challengeComm = ChallengeComm.ChallengeComm()
	def getChallengeTupple(self):
		chalTup = self.challengeComm.getNextChallenge()
		mask = self.getMaskSize()
		return (chalTup[0], chalTup[1], mask)

	def getMaskSize(self):
		return 17

