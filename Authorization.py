import RequestAuthority

class Auth():
	def __init__(self):
		self.ra = RequestAuthority.RequestAuthority()
		self.stage = 0

	def getResponse(self, request):
		self.processRequest(request)
		return none

	def processRequest(self,request):
		return none
