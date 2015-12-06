import SocketServer
import Consts as c
import argparse
import socket
import datetime
import os
import Utilities as util
import Authentication


nonce_dict = {}
auth_dict = {}
g = 0
p = 0

class ChatRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        '''
        Perform packet handling logic
        '''
        global auth_dict, g, p, nonce_dict
        msg = self.request[0]
        sock = self.request[1]

        # get auth instance for client
        if self.client_address not in auth_dict:
            # new client, create an auth entry in the auth dictionary
            auth_dict[self.client_address] = Authentication.Authentication(self.client_address, p, g)
        cur_auth = auth_dict[self.client_address]
        assert isinstance(cur_auth, Authentication.Authentication)
        # TODO handle request, do the timestamp and nonce in handler class
        if not cur_auth.is_auth():
            rep = cur_auth.process_request(msg)
        else:
            rep = None  # TODO get reponse for keep-alive, list, chat and logout
            rep = rep # TODO encrypted response

        try:
            sock.sendto(rep, self.client_address)
        except socket.error:
            print c.FAIL_MSG_FWD
            return


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
    # addr_set = {}
    # nonce_dict = {}
    parser = argparse.ArgumentParser()
    parser.add_argument('-sp', required=True, type=int)
    opts = parser.parse_args()
    run_server(opts.sp)
