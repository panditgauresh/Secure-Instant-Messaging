import socket
import sys
import threading
import Consts
import argparse
import datetime
import Utilities as util
from CryptoService import CryptoService
from ClientServerAuthentication import ClientServerAuthentication
from ClientClientAuthentication import ClientClientAuthentication
import Consts as c
from UserInputHandler import UserInputHandler
from PacketOrganiser import PacketOrganiser
from ClientChattingService import ClientChattingService

server_auth = None
active_users = []  # active user list from server
addr_auths = {}  # addr : auth
user_addr_dict = {}  # username : addr
nonce_auths = {}  # nonce : auth for pre-auth (get TTB from server)
pending_response = {}
packetorg = PacketOrganiser()

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
        global user_addr_dict, nonce_auths, pending_response, packetorg, server_auth
        while self.listen:
            # waiting for user input
            user_input = sys.stdin.readline()
            packetorg.user_addr_dict = user_addr_dict
            if user_input:
                # LIST,
                handler = UserInputHandler(server_auth, user_addr_dict, addr_auths, nonce_auths, active_users)
                type, addr, out_msg = handler.handle_input(user_input, packetorg)  # Consts.MSG_HEAD + user_input + datetime.datetime.now().strftime("%H:%M:%S:%f")
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
    global server_auth, user_auths, user_addr_dict, active_users
    g = 2
    p = util.load_df_param_from_file("files/df_param")
    crypto_service = CryptoService(rsa_pub_path=c.PUB_KEY_PATH, p=p, g=g)
    # crypto_service = FakeCryptoService(rsa_pub_path=c.PUB_KEY_PATH, p=p, g=g)   # TODO for test
    chat_service = ClientChattingService(active_users)

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

    server_auth = ClientServerAuthentication(client_addr, server_addr, crypto_service)

    try:
        server_auth.start_authenticate(sock)
    except socket.error:
        print Consts.FAIL_GRE_MSG
        return

    # start a background to handle user input
    t = ListenThread(sock, server_addr)
    t.start()

    sys.stdout.write(Consts.PROMPT)
    sys.stdout.flush()

    # sock.settimeout(1)

    while True:
        try:
            # listening to the server and display the message
            recv_msg, r_addr = sock.recvfrom(20480)
            if r_addr == server_addr and recv_msg:
                dec_msg = crypto_service.sym_decrypt(server_auth.dh_key, recv_msg)
                pending_response.pop("key", None)
                n, ts, msg_ps = PacketOrganiser.process_packet(dec_msg)
                if PacketOrganiser.isValidTimeStamp(ts):  # TODO for testing
                    # first check if it's a client/client authentication
                    # response from server
                    if n in nonce_auths:
                        # TODO process the auth response from server
                        cur_auth = nonce_auths.pop(n)
                        assert isinstance(cur_auth, ClientClientAuthentication)
                        b_addr = cur_auth.start_authenticate(sock, msg_ps)
                        addr_auths[b_addr] = cur_auth

                    else:
                        chat_service.process_message(msg_ps)
                else:
                    print("Time stamp invalid!")
                # if recv_msg.startswith(Consts.MSG_HEAD):
                #     sys.stdout.write('\r<- {}'.format(recv_msg[2:]))
                #     sys.stdout.write(Consts.PROMPT)
                #     sys.stdout.flush()
            elif r_addr in user_addr_dict:   #Reply or chat request from client
                dh_key = user_auths[user_addr_dict[r_addr]][1]
                decrypt_msg = crypto_service.sym_decrypt(dh_key, recv_msg)

                pass

        except socket.timeout:
            for key, value in pending_response.items():
                if packetorg.hasTimedOut(value):
                    sock.sendto(packetorg.modifyTimeStamp(value, server_auth), server_addr)
            continue
        except KeyboardInterrupt:
            # when seeing ctrl-c terminate the client
            t.stop()
            t.join()
            print Consts.BYE
            break
            pass
    sock.close()


if __name__ == '__main__':
    # parser = argparse.ArgumentParser()
    # parser.add_argument('-sip', required=True)
    # parser.add_argument('-sp', required=True, type=int)
    # opts = parser.parse_args()
    # run_client(opts.sip, opts.sp)
    run_client('192.168.15.1', 9090)
