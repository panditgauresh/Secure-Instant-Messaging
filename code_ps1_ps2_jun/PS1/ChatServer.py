import SocketServer
import Consts as c
import argparse
import socket


class ChatRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        '''
        When seeing GREETING message, add the address to the set.
        When seeing INCOMING message, forward to all the subscribed clients.
        '''
        global addr_set

        msg = self.request[0]
        if msg == c.GREETING:  # handling GREETING messages
            addr_set.add(self.client_address)
        else:  # handling INCOMING messages
            if msg.startswith(c.MSG_HEAD) and self.client_address in addr_set:
                addr_str = self.client_address[0] + ':' + \
                           str(self.client_address[1])
                out_msg = c.FWD_MSG.format(c.MSG_HEAD, addr_str, msg[2:])
                sock = self.request[1]
                for addr in addr_set:
                    try:
                        sock.sendto(out_msg, addr)
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
    addr_set = set()
    parser = argparse.ArgumentParser()
    parser.add_argument('-sp', required=True, type=int)
    opts = parser.parse_args()
    run_server(opts.sp)
