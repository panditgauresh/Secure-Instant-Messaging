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
active_users = {}  # active user list from server
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
        global user_addr_dict, nonce_auths, pending_response, packetorg, server_auth, active_users
        while self.listen:
            # waiting for user input
            user_input = sys.stdin.readline()
            packetorg.user_addr_dict = user_addr_dict
            if user_input:
                # LIST,
                handler = UserInputHandler(server_auth, user_addr_dict, addr_auths, nonce_auths, active_users)
                type, addr, out_msg = handler.handle_input(user_input, packetorg)
                if addr:
                    if addr == self.server_addr:
                        pending_response[type] = packetorg.addTimeStamp(out_msg)
                    try:
                        # print("sending msg len: {}".format(len(out_msg)))
                        self.sock.sendto(out_msg, addr)
                    except socket.error:
                        print c.FAIL_SEND
                    sys.stdout.write(Consts.PROMPT)
                    sys.stdout.flush()
                elif out_msg:
                    sys.stdout.write(out_msg)
                    sys.stdout.write("\n")
                    sys.stdout.write(Consts.PROMPT)
                    sys.stdout.flush()
                else:
                    sys.stdout.write(Consts.ERR_CMD)
                    sys.stdout.write("\n")
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

    chat_service = ClientChattingService(active_users, server_auth)

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
                n, msg_ps = PacketOrganiser.process_packet(dec_msg)
                # first check if it's a client/client authentication
                # response from server
                if n in nonce_auths:
                    # TODO process the auth response from server
                    cur_auth = nonce_auths.pop(n)
                    assert isinstance(cur_auth, ClientClientAuthentication)
                    b_addr = cur_auth.start_authenticate(sock, msg_ps, server_auth.username)
                    user_addr_dict[cur_auth.username] = b_addr
                    addr_auths[b_addr] = cur_auth
                else:
                    chat_service.process_message(msg_ps)
            elif r_addr in addr_auths:   #Reply or chat request from client
                # print("recv msg len: {}".format(len(recv_msg)))
                cur_auth = addr_auths[r_addr]
                encrypt_msg, signature = packetorg.divide_signature(recv_msg)
                if not packetorg.is_signature_match(cur_auth.dh_key, encrypt_msg, signature):
                    print "Message from "+ cur_auth.username + " has be tampered. Packet Dropped."
                    continue
                dec_msg = crypto_service.sym_decrypt(cur_auth.dh_key, recv_msg)

                n, dec_msg_parts = PacketOrganiser.process_packet(dec_msg)


                type = dec_msg_parts[0]
                if type == c.MSG_RESPONSE_OK:

                    # verify nonce
                    if n != cur_auth.last_nonce:
                        continue
                    if not cur_auth.complete_auth():
                        # deal with peer auth success msg
                        cur_auth.auth_success = True
                        util.display_user_message(dec_msg_parts[1], cur_auth.username)
                    else:
                        # TODO deal with msg confirm
                        pass
                elif type == c.MSG_TYPE_MSG:
                    # display user message
                    util.display_user_message(dec_msg_parts[1], cur_auth.username)
                elif type == c.MSG_TYPE_PUB_KEY:
                    # finish peer authentication on Alice side
                    b_pub_key = int(dec_msg_parts[1])
                    cur_auth.dh_key = crypto_service.get_dh_secret(cur_auth.pri_key, b_pub_key)
                    cur_auth.auth_success = True
                    cur_auth.last_nonce = n
                    # send confirmation and first message to Bob
                    conf_msg_parts = [c.MSG_RESPONSE_OK, cur_auth.first_msg, ""]
                    conf_msg = PacketOrganiser.prepare_packet(conf_msg_parts, n)
                    enc_conf_msg = crypto_service.sym_encrypt(cur_auth.dh_key, conf_msg)
                    sock.sendto(enc_conf_msg, r_addr)

            else: # TODO the r_addr not in user_addr_dict, this can be a TTB, a DDOS weakness?
                _, msg_ps = PacketOrganiser.process_packet(recv_msg)
                signed_ttb, enc_inside_msg, _ = msg_ps
                ttb = signed_ttb[:-512]
                sign = signed_ttb[-512:]
                if not crypto_service.rsa_verify(ttb, sign):  # TODO for testing
                    raise Exception("Ticket To B corrupted!")
                dec_ttb = crypto_service.sym_decrypt(server_auth.dh_key, ttb)
                _, ttb_parts = PacketOrganiser.process_packet(dec_ttb)  # a_username, a_addr, k_ab
                a_username_ttb, a_addr, k_ab = ttb_parts
                a_addr = util.str_to_addr(a_addr)
                # decrypt inside message with k_ab
                dec_inside_msg = crypto_service.sym_decrypt(k_ab, enc_inside_msg)
                _, inside_msg_parts = PacketOrganiser.process_packet(dec_inside_msg)
                a_username, a_pub_key, _ = inside_msg_parts
                # print("username_ttb: {}, a_username: {}".format(a_username_ttb, a_username))
                if a_username_ttb != a_username:
                    raise Exception("Username not match in the TTB!")
                new_auth = ClientClientAuthentication(a_username, crypto_service)
                pri_key = crypto_service.get_dh_pri_key()
                pub_key = crypto_service.get_dh_pub_key(pri_key)
                new_auth.dh_key = crypto_service.get_dh_secret(pri_key, int(a_pub_key))
                nonce = util.get_good_nonce(nonce_auths)
                new_auth.last_nonce = nonce
                # send pub key to a
                msg_parts = [c.MSG_TYPE_PUB_KEY, pub_key, ""]
                plain_msg = PacketOrganiser.prepare_packet(msg_parts, nonce)
                enc_msg = crypto_service.sym_encrypt(k_ab, plain_msg)
                sock.sendto(enc_msg, a_addr)
                # add new auth to dict
                addr_auths[a_addr] = new_auth
                user_addr_dict[a_username] = a_addr

        except socket.timeout:
            for key, value in pending_response.items():
                if packetorg.hasTimedOut(value):
                    sock.sendto(packetorg.modifyTimeStamp(value, server_auth), server_addr)
            continue
        except KeyboardInterrupt:
            # when seeing ctrl-c terminate the client
            t.stop()
            t.join()
            print c.BYE
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
    # run_client('10.102.57.249', 9090)
