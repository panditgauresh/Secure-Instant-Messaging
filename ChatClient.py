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
import time

server_auth = None
active_users = {}  # active user list from server
addr_auths = {}  # addr : auth
user_addr_dict = {}  # username : addr
request_cache = {}  # nonce : [request type, msg, key, addr, ts, auth for pre-auth <get TTB from server> (if any)]
packetorg = PacketOrganiser()


class ListenThread(threading.Thread):
    def __init__(self, sock, saddr):
        """
        sock: socket used for sending message to server
        saddr: server address
        """
        threading.Thread.__init__(self)
        self.sock = sock
        self.listen = True  # flag for terminate the thread
        self.server_addr = saddr


    def run(self):
        """
        Handling user input and sending message to the server.
        """
        global user_addr_dict, request_cache, packetorg, server_auth, active_users
        while self.listen:
            # waiting for user input
            user_input = sys.stdin.readline()
            packetorg.user_addr_dict = user_addr_dict
            if user_input:
                # The handler handles any input that comes to the client and sends the desired output message.
                # Depending on the input the output message and the address are received.
                handler = UserInputHandler(server_auth, user_addr_dict, addr_auths, request_cache, active_users)
                type, addr, out_msg = handler.handle_input(user_input)
                if addr:
                    try:
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
        """
        Terminate the thread by unsetting the flag.
        """
        sys.stdout.write(Consts.TERM_MSG)
        sys.stdout.flush()
        self.listen = False


class ResendThread(threading.Thread):
    """
    Thread for message resending.
    """
    def __init__(self, sock, request_cache):
        """
        sock: socket used for sending message to server
        saddr: server address
        """
        threading.Thread.__init__(self)
        self.sock = sock
        self.resending = True  # flag for terminate the thread
        self.request_cache = request_cache


    def run(self):
        """
        A new thread for resending any message in the cache.
        This thread also sends keep-alive messages every thirty seconds.
        """
        i = 0
        while self.resending:
            time.sleep(c.RESEND_SLEEP_SEC)
            i = i + 2
            if i == 30:
                i = 0
                self.send_keep_alive()
            caches_to_remove = []
            for nonce, cache in self.request_cache.iteritems():
                ts = cache[c.CACHE_TS_IND]
                if not PacketOrganiser.isValidTimeStamp(ts, c.TS_RESEND_MICRO_SEC):
                    if not self.resend(cache):
                        caches_to_remove.append(nonce)
            for n in caches_to_remove:
                self.request_cache.pop(n)

    def send_keep_alive(self):
        """
        Sends a keep alive message to the server.
        """
        global server_auth
        res_msg = PacketOrganiser.prepare_packet(c.MSG_TYPE_KEEP_ALIVE)
        encrypt_msg = server_auth.crypto_service.sym_encrypt(server_auth.dh_key, res_msg)
        self.sock.sendto(encrypt_msg, server_auth.server_addr)

    def resend(self, cache):
        """
        :param cache: The parameter cache stores what message haven't acknowledged to resend them.
        :return: True if resend happened, False otherwise
        """
        global server_auth
        # first check if the cache is more than 30 seconds old
        # if it is, we will drop the cache entry, which means the other side is off line, don't resend again
        if cache[c.CACHE_TYPE_IND] == c.MSG_TYPE_MSG:
            original_ts = self.get_original_ts(cache)
            if not PacketOrganiser.isValidTimeStampSeconds(original_ts, 30):
                util.cmd_output("Stop message resending.")
                return False

        ts = PacketOrganiser.get_new_timestamp()
        cache[c.CACHE_TS_IND] = ts
        msg = util.replace_ts_in_msg(cache[c.CACHE_MSG_IND])
        # cache[c.CACHE_MSG_IND] = msg
        enc_msg = server_auth.crypto_service.sym_encrypt(cache[c.CACHE_KEY_IND], msg)
        self.sock.sendto(enc_msg, cache[c.CACHE_ADDR_IND])
        return True

    def get_original_ts(self, cache):
        """
        :param cache: The parameter cache stores what message haven't acknowledged to resend them.
        :return: Gets the timestamp from the cache
        """
        msg = cache[c.CACHE_MSG_IND]
        return msg[-c.TS_LEN:]

    def stop(self):
        """
        Terminate the thread by unsetting the flag.
        """
        sys.stdout.write(Consts.TERM_MSG)
        sys.stdout.flush()
        self.resending = False


def run_client(server_ip, server_port):
    """
    Main function to start the client.
    server_ip: IP address of the server
    server_port: port number which server uses to communicate
    """
    global server_auth, user_auths, user_addr_dict, active_users
    g = 2
    p = util.load_df_param_from_file(c.DH_CONFIG_PATH)
    crypto_service = CryptoService(rsa_pub_path=c.PUB_KEY_PATH, p=p, g=g)

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
        server_auth.authenticate_with_server(sock)
    except socket.error:
        print Consts.FAIL_GRE_MSG
        return

    chat_service = ClientChattingService(active_users, server_auth)

    # start a background to handle user input
    t_listen = ListenThread(sock, server_addr)
    t_listen.start()

    # start a background to resend message
    t_resend = ResendThread(sock, request_cache)
    t_resend.start()

    sys.stdout.write(Consts.PROMPT)
    sys.stdout.flush()

    while True:
        try:
            # listening to the server and display the message
            recv_msg, r_addr = sock.recvfrom(20480)
            if r_addr == server_addr and recv_msg:
                dec_msg = crypto_service.sym_decrypt(server_auth.dh_key, recv_msg)
                n, msg_ps = PacketOrganiser.process_packet(dec_msg)
                # first check if it's a client/client authentication
                # response from server
                if n in request_cache:
                    # check the type of request
                    cache = request_cache[n]
                    request_type = cache[c.CACHE_TYPE_IND]
                    if request_type == c.MSG_TYPE_LOGOUT:
                        # process logout confirmation
                        if msg_ps[0] == c.MSG_RESPONSE_OK:
                            request_cache.pop(n)
                            break
                    elif request_type == c.MSG_TYPE_START_NEW_CHAT:
                        # process the auth response from server
                        cur_auth = cache[c.CACHE_AUTH_IND]
                        assert isinstance(cur_auth, ClientClientAuthentication)
                        b_addr = cur_auth.start_authenticate(sock, msg_ps, server_auth.username)
                        user_addr_dict[cur_auth.username] = b_addr
                        addr_auths[b_addr] = cur_auth
                        request_cache.pop(n)
                    elif request_type == c.MSG_TYPE_LIST:
                        # process the user list form server
                        chat_service.process_message(msg_ps)
                        request_cache.pop(n)
                    elif request_type == c.ERR_CLIENT_DOWN:
                        print(c.ERR_CLIENT_DOWN)
                        request_cache.pop(n)
            elif r_addr in addr_auths:   #Reply or chat request from client
                cur_auth = addr_auths[r_addr]
                dec_msg = crypto_service.sym_decrypt(cur_auth.dh_key, recv_msg)

                n, dec_msg_parts = PacketOrganiser.process_packet(dec_msg)
                type = dec_msg_parts[0]

                if cur_auth.auth_success:
                    if type == c.MSG_RESPONSE_OK:
                        if n in request_cache:
                            cache = request_cache[n]
                            request_type = cache[c.CACHE_TYPE_IND]
                            if request_type == c.MSG_TYPE_MSG:
                                request_cache.pop(n)
                                continue

                    elif type == c.MSG_TYPE_MSG:
                        # display user message
                        msg_hmac = dec_msg_parts[1]
                        # check the HMAC
                        msg, sign = PacketOrganiser.divide_signature(msg_hmac)
                        if CryptoService.verify_hmac_sign(cur_auth.dh_key, msg, sign):
                            util.display_user_message(msg, cur_auth.username)
                            # send message confirmation back
                            util.send_confirmation(sock, crypto_service, cur_auth.dh_key, n, r_addr)
                else:
                    # deal with peer auth success msg
                    if type == c.MSG_RESPONSE_OK:
                        if n in request_cache:
                            cache = request_cache[n]
                            request_type = cache[c.CACHE_TYPE_IND]
                            if request_type == c.MSG_TYPE_PUB_KEY:
                                # verify nonce
                                if n != cur_auth.last_nonce:
                                    continue
                                else:
                                    cur_auth.auth_success = True
                                    request_cache.pop(n)
                                    # check the HMAC
                                    msg_hmac = dec_msg_parts[1]
                                    msg, sign = PacketOrganiser.divide_signature(msg_hmac)
                                    if CryptoService.verify_hmac_sign(cur_auth.dh_key, msg, sign):
                                        # display user message
                                        util.display_user_message(msg, cur_auth.username)
                                        # send message confirmation back
                                        util.send_confirmation(sock, crypto_service, cur_auth.dh_key, n, r_addr)

                    elif type == c.MSG_TYPE_PUB_KEY:
                        # finish peer authentication on Alice side
                        b_pub_key = int(dec_msg_parts[1])
                        cur_auth.dh_key = crypto_service.get_dh_secret(cur_auth.pri_key, b_pub_key)
                        cur_auth.auth_success = True
                        cur_auth.last_nonce = n
                        # send confirmation and first message to Bob
                        hmac = CryptoService.generate_hmac_sign(cur_auth.dh_key, cur_auth.first_msg)
                        first_msg_hmac = cur_auth.first_msg + hmac
                        conf_msg_parts = [c.MSG_RESPONSE_OK, first_msg_hmac, ""]
                        conf_msg = PacketOrganiser.prepare_packet(conf_msg_parts, n)
                        enc_conf_msg = crypto_service.sym_encrypt(cur_auth.dh_key, conf_msg)
                        # add to request cache
                        # a hack here (TYPE_MSG instead of RESPONSE_OK) to make the confirmation work
                        util.add_to_request_cache(request_cache, n, c.MSG_TYPE_MSG, cur_auth.dh_key, conf_msg, r_addr)
                        sock.sendto(enc_conf_msg, r_addr)
            else: # the r_addr not in user_addr_dict, this can be a TTB
                # handle TTB from Alice
                _, msg_ps = PacketOrganiser.process_packet(recv_msg)
                signed_ttb, enc_inside_msg, _ = msg_ps
                ttb = signed_ttb[:-c.RSA_SIGN_LENGTH]
                sign = signed_ttb[-c.RSA_SIGN_LENGTH:]
                if not crypto_service.rsa_verify(ttb, sign):
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
                nonce = util.get_good_nonce(request_cache)
                new_auth.last_nonce = nonce
                # send pub key to Alice
                msg_parts = [c.MSG_TYPE_PUB_KEY, pub_key, ""]
                plain_msg = PacketOrganiser.prepare_packet(msg_parts, nonce)
                enc_msg = crypto_service.sym_encrypt(k_ab, plain_msg)
                sock.sendto(enc_msg, a_addr)
                # add new auth to dict
                addr_auths[a_addr] = new_auth
                user_addr_dict[a_username] = a_addr
                util.add_to_request_cache(request_cache, nonce, c.MSG_TYPE_PUB_KEY, k_ab, plain_msg, a_addr) # add to request cache
        except socket.error:
            # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # sock.bind(client_addr)
            continue
        except KeyboardInterrupt:
            # when seeing ctrl-c terminate the client
            t_listen.stop()
            t_listen.join()
            t_resend.stop()
            t_resend.join()
            print c.BYE
            server_auth.logout(sock)
            sock.close()
            return
        except:
            pass
    t_listen.stop()
    t_listen.join()
    t_resend.stop()
    t_resend.join()
    print c.BYE
    server_auth.logout(sock)
    sock.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-sip', required=True)
    parser.add_argument('-sp', required=True, type=int)
    opts = parser.parse_args()
    run_client(opts.sip, opts.sp)
    # run_client('192.168.1.9', 9090)