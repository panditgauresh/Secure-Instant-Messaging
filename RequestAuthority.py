import ChallengeComm

class RequestAuthority():
	def __init__(self):
		self.challengeComm = ChallengeComm.ChallengeComm()
	def getChallengeTupple():
		chalTup = self.challengeComm.getNextChallenge()
		mask = self.getMaskSize()
		return (chalTup[0], chalTup[1], mask)

	def getMaskSize():
		return 17
