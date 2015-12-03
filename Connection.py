import Authorization
import datetime
import DH
import Communicator

class Connection():
	def __init__(self, addr):
		self.auth = Authorization.Auth()
		self.stage = 'Auth'
		self.addr = addr
		self.timestamp = datetime.datetime.now().strptime(timestamp,"%H:%M:%S:%f")
		#self.dh = DH.DiffieHellman()
		self.comm = Communicator.Comm()

	def getResponse(self, message):
		if(self.stage == 'Auth'):
			return auth.getResponse(message)
		else:
			return comm.getResponse(message)
