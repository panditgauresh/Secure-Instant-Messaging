import socket
import sys
import threading
import Consts
import argparse
import datetime

class ListenThread (threading.Thread):

    def __init__(self, sock, saddr):
        '''
        sock: socket used for sending message to server
        saddr: server address
        '''
        threading.Thread.__init__(self)
        self.sock = sock
        self.listen = True  # flag for terminate the thread
        self.server_addr = saddr

    def run(self):
        '''
        Handling user input and sending message to the server.
        '''
        while self.listen:
            # waiting for user input
            user_input = sys.stdin.readline()
            if user_input:
                out_msg = Consts.MSG_HEAD + user_input + datetime.datetime.now().strftime("%H:%M:%S:%f")
                try:
                    self.sock.sendto(out_msg, self.server_addr)
                except socket.error:
                    print Consts.FAIL_SEND
                    pass
                sys.stdout.write(Consts.PROMPT)
                sys.stdout.flush()

    def stop(self):
        '''
        Terminate the thread by unsetting the flag.
        '''
        sys.stdout.write(Consts.TERM_MSG)
        sys.stdout.flush()
        self.listen = False


def run_client(server_ip, server_port):
    '''
    Main function to start the client.
    server_ip: IP address of the server
    server_port: port number which server uses to communicate
    '''
    server_addr = (server_ip, server_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_port = server_port
    local_ip = socket.gethostbyname(socket.gethostname())
    client_addr = (local_ip, client_port)

    # try to find a available local port
    port_found = False
    while not port_found:
        try:
            sock.bind(client_addr)
            port_found = True
        except socket.error:
            client_addr = (client_addr[0], client_addr[1] + 1)
            continue

    try:
        sock.sendto(Consts.GREETING, server_addr)
    except socket.error:
        print Consts.FAIL_GRE_MSG
        return

    # start a background to handle user input
    t = ListenThread(sock, server_addr)
    t.start()

    sys.stdout.write(Consts.PROMPT)
    sys.stdout.flush()

    try:
        while True:
            # listening to the server and display the message
            recv_msg, r_addr = sock.recvfrom(1024)
            if r_addr == server_addr and recv_msg:
                if recv_msg.startswith(Consts.MSG_HEAD):
                    sys.stdout.write('\r<- {}'.format(recv_msg[2:]))
                    sys.stdout.write(Consts.PROMPT)
                    sys.stdout.flush()
    except KeyboardInterrupt:
        # when seeing ctrl-c terminate the client
        t.stop()
        t.join()
        print Consts.BYE
        pass
    finally:
        sock.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-sip', required=True)
    parser.add_argument('-sp', required=True, type=int)
    opts = parser.parse_args()
    run_client(opts.sip, opts.sp)
