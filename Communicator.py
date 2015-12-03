class Comm():
	def __init__(self):
		pass

	def getResponse(self, message):
		msgType = getMessageType(message)
		if(msgType == 'List'):
			pass
		elif(msgType == 'Chat'):
			pass
		elif(msgType == 'Keep-Alive'):
			pass
		else:
			pass  #Error Condition

	def getMessageType(self,message):
		return 'List'
