import socket
import sys
import threading
import Consts
import argparse
import datetime
import Utilities as util
from CryptoService import CryptoService
from FakeCryptoService import FakeCryptoService
from ClientAuthentication import ClientAuthentication
import Consts as c
import UserInputHandler
import PacketOrganiser

client_auth = None
known_users = {}
pending_response = {}
packetorg = PacketOrganiser.PacketOrganiser()

class ListenThread(threading.Thread):
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
        global knonwn_users
        global pending_response
        global packetorg
        while self.listen:
            # waiting for user input
            user_input = sys.stdin.readline()
            if user_input:
                # LIST,
                handler = UserInputHandler.UserInputHandler()
                type, addr, out_msg = handler.handle_input(user_input, packetorg, known_users,
                                                              self.server_addr)  # Consts.MSG_HEAD + user_input + datetime.datetime.now().strftime("%H:%M:%S:%f")
                if addr:
                    if addr == self.server_addr:
                        pending_response[type] = packetorg.addTimeStamp(out_msg)
                    try:
                        self.sock.sendto(out_msg, addr)
                    except socket.error:
                        print Consts.FAIL_SEND
                        pass
                    sys.stdout.write(Consts.PROMPT)
                    sys.stdout.flush()
                elif out_msg:
                    sys.stdout.write(out_msg)
                    sys.stdout.flush()
                else:
                    sys.stdout.write(Consts.ERR_CMD)
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
    global client_auth
    g = 2
    p = util.load_df_param_from_file("files/df_param")
    crypto_service = CryptoService(rsa_pub_path=c.PUB_KEY_PATH, p=p, g=g)
    # crypto_service = FakeCryptoService(rsa_pub_path=c.PUB_KEY_PATH, p=p, g=g)   # TODO for test

    server_addr = (server_ip, server_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_port = server_port + 1
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

    client_auth = ClientAuthentication(client_addr, server_addr, crypto_service)

    try:
        client_auth.start_authentication(sock)
    except socket.error:
        print Consts.FAIL_GRE_MSG
        return

    # start a background to handle user input
    t = ListenThread(sock, server_addr)
    t.start()

    sys.stdout.write(Consts.PROMPT)
    sys.stdout.flush()

    sock.settimeout(1)

    while True:
        try:
            # listening to the server and display the message
            recv_msg, r_addr = sock.recvfrom(1024)
            if r_addr == server_addr and recv_msg:
                decrypt_msg = client_auth.crypto_service.sym_decrypt(recv_msg)
                #decrypt_msg.split(",")
                pending_response.pop("key", None)
                if recv_msg.startswith(Consts.MSG_HEAD):
                    sys.stdout.write('\r<- {}'.format(recv_msg[2:]))
                    sys.stdout.write(Consts.PROMPT)
                    sys.stdout.flush()
            else:   #Reply or chat request from client
                pass

        except socket.timeout:
            for key, value in pending_response:
                if packetorg.hasTimedOut(value):
                    sock.sendto(packetorg.modifyTimeStamp(value, client_auth),server_addr)
            continue
        except KeyboardInterrupt:
            # when seeing ctrl-c terminate the client
            t.stop()
            t.join()
            print Consts.BYE
            break
            pass
        finally:
            sock.close()


if __name__ == '__main__':
    # parser = argparse.ArgumentParser()
    # parser.add_argument('-sip', required=True)
    # parser.add_argument('-sp', required=True, type=int)
    # opts = parser.parse_args()
    # run_client(opts.sip, opts.sp)
    run_client('192.168.15.1', 9090)
