import SocketServer
import Consts as c
import argparse
import socket
import datetime
import os
import Connection

class ChatRequestHandler(SocketServer.BaseRequestHandler):

	def genRandomNumber(self, bit_size):
		return int(os.urandom(bit_size).encode('hex'),16)

	def addTimeStamp(self,out_msg):
		return str(out_msg) + datetime.datetime.now().strftime("%H:%M:%S:%f")

    def verifyNonce(self,msg,addr,nonce_dict):
        nonce = msg.rsplit('\n',1)[1]
        if(nonce_dict[addr] == nonce):
            return True
        return False

	def addNonce(self,out_msg,addr,nonce_dict):
		nonce_dict[addr] = self.genRandomNumber(8)
		return str(out_msg) + "\n" + str(nonce_dict[addr])

    def retrieveOrigMsg(self,out_msg):
        out_msg = out_msg.rsplit('\n',1)[0]
        print("out Message:"+str(out_msg))
        return out_msg

    def isValidTimeStamp(self,message, indexOfMessage):
        timestamp = message.rsplit('\n',1)[1]
        recvTime = datetime.datetime.strptime(timestamp,"%H:%M:%S:%f")
        timeNow = datetime.datetime.now().strptime(timestamp,"%H:%M:%S:%f")
        print(message)
        print("timestamp")
        print(timeNow)
        print(recvTime)
        diff = timeNow - recvTime
        print(diff)
        #if(diff.days == 0 and diff.hours == 0 and diff.minutes == 0 and diff.seconds == 0):
        #  if(abs(diff.microseconds) < 500):
        if(diff.days == 0 and abs(diff) < datetime.timedelta(microseconds=200)):
            return True
            #print(diff.strftime("%H:%M:%S:%f"))
        print(diff)
        return False

    	def handle(self):
        	'''
	        When seeing GREETING message, add the address to the set.
	        When seeing INCOMING message, forward to all the subscribed clients.
        	'''
	        global addr_set
		global nonce_dict
	        msg = self.request[0]
		#recvNonce = self.verifyNonce(msg,self.client_address,nonce_dict)
		#curr_msg = self.retrieveOrigMsg(msg)
        	if msg == c.GREETING:  # handling GREETING messages
		    addr_set[self.client_address] = Connection.Connection(self.client_address)#ra.getChallengeTupple()
	            #addr_set.add(self.client_address)
        	else:  # handling INCOMING messages
	            if msg.startswith(c.MSG_HEAD) and self.client_address in addr_set:
        	        addr_str = self.client_address[0] + ':' + \
	                           str(self.client_address[1])
	                out_msg = c.FWD_MSG.format(c.MSG_HEAD, addr_str, msg[2:])
	                print(msg[2:]+' and '+msg)
			out_msg = self.retrieveOrigMsg(out_msg)
        	        if(self.isValidTimeStamp(msg[2:],0)):
                	  sock = self.request[1]
	                  for addr in addr_set:
        	            try:
				nonceMsg = self.addNonce(self.addTimeStamp(out_msg),addr,nonce_dict)
	                        sock.sendto(nonceMsg , addr)
        	            except socket.error:
                	        print c.FAIL_MSG_FWD
	                        return
        	        else:
                	  print("Timestamp is Invalid")


def run_server(port):
    '''
    Main function to run the server.
    '''
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        serv = SocketServer.UDPServer((local_ip, port), ChatRequestHandler)
    except socket.error:
        print c.FAIL_SRV_INIT
        return

    print c.SRV_START

    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        # Stop server when seeing ctrl-c
        pass
    except:
        print c.FAIL_SRV_START
    finally:
        serv.server_close()

if __name__ == '__main__':
    addr_set = {}
    nonce_dict = {}
    parser = argparse.ArgumentParser()
    parser.add_argument('-sp', required=True, type=int)
    opts = parser.parse_args()
    run_server(opts.sp)
