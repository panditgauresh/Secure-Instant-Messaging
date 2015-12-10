import SocketServer
import Consts as c
import argparse
import socket
import os
import Utilities as util
import Authentication
from CryptoService import CryptoService
from PacketOrganiser import PacketOrganiser
from ChattingService import ChattingService
import sys

nonce_dict = {}
auth_dict = {}
crypto_service = None
chatting_service = None
password_hash_dict = {}
user_addr_dict = {}


class ChatRequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        '''
        Perform packet handling logic
        '''
        global auth_dict, nonce_dict, crypto_service, password_hash_dict, user_addr_dict, chatting_service
        msg = self.request[0]
        sock = self.request[1]
        # print('Message received from {}: {}'.format(self.client_address, msg))
        # get auth instance for client
        if self.client_address not in auth_dict:
            if msg != c.GREETING:
                return
            # new client, create an auth entry in the auth dictionary
            auth_dict[self.client_address] = Authentication.Authentication(self.client_address, crypto_service,
                                                                           password_hash_dict)
        cur_auth = auth_dict[self.client_address]
        assert isinstance(cur_auth, Authentication.Authentication)
        # TODO handle request, do the timestamp and nonce in handler class
        rep = None
        if not cur_auth.is_auth():
            rep = cur_auth.process_request(msg, user_addr_dict)

        else:
            # get decrypted msg
            dec_msg = crypto_service.sym_decrypt(cur_auth.dh_key, msg)
            n, msg_ps = PacketOrganiser.process_packet(dec_msg)
            auth_dict[self.client_address].timestamp = PacketOrganiser.get_new_timestamp()  # update timestamp
            rep = chatting_service.get_response(self.client_address, msg_ps)
            if rep is not None:
                rep = PacketOrganiser.prepare_packet(rep, n)
                rep = crypto_service.sym_encrypt(cur_auth.dh_key, rep)  # TODO encrypted response

        try:
            if rep is not None:
                # print("Sending msg length {}: {}".format(len(rep), rep))
                sys.stdout.flush()
                sock.sendto(rep, self.client_address)
        except socket.error:
            print(c.FAIL_MSG_FWD)
            return


def run_server(port):
    '''
    Main function to run the server.
    '''
    # load config file for DH and username/password
    global crypto_service, password_hash_dict, chatting_service, user_addr_dict, auth_dict
    g = c.DH_GENERATOR
    p = util.load_df_param_from_file("files/df_param")
    crypto_service = CryptoService(rsa_pri_path=c.PRI_KEY_PATH, p=p, g=g)
    chatting_service = ChattingService(user_addr_dict, auth_dict, crypto_service)
    pw_dict_path = "files/pw_hash_dict"
    password_hash_dict = util.load_pickle_file(pw_dict_path)
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        print('Binding to ip: {}'.format(local_ip))
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
    # parser = argparse.ArgumentParser()
    # parser.add_argument('-sp', required=True, type=int)
    # opts = parser.parse_args()
    # run_server(opts.sp)
    run_server(9090)
