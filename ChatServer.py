import SocketServer
import Consts as c
import argparse
import socket
import os
import Utilities as util
from Authentication import Authentication
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


class ClientRequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        """
        Handle requests from the clients.
        :return:
        """
        global auth_dict, nonce_dict, crypto_service, password_hash_dict, user_addr_dict, chatting_service
        msg = self.request[0]
        sock = self.request[1]
        # get auth instance for client
        if self.client_address not in auth_dict:
            try:
                _, msg_parts = PacketOrganiser.process_packet(msg)
            except:
                return
            if msg_parts[0] != c.GREETING:
                return
            # new client, create an auth entry in the auth dictionary
            auth_dict[self.client_address] = Authentication(self.client_address, crypto_service,
                                                                           password_hash_dict)
        else:
            auth = auth_dict[self.client_address]
            if not PacketOrganiser.isValidTimeStampSeconds(auth.timestamp,c.KEEP_ALIVE_TIME):
                auth_dict.pop(self.client_address)

        cur_auth = auth_dict[self.client_address]
        assert isinstance(cur_auth, Authentication)
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
                rep = crypto_service.sym_encrypt(cur_auth.dh_key, rep)

        try:
            if rep is not None:
                sys.stdout.flush()
                sock.sendto(rep, self.client_address)
            elif cur_auth.is_auth():
                cur_auth.loginfailures += 1
        except socket.error:
            print(c.FAIL_MSG_FWD)
            return


def run_server(port):
    """
    Main function to run the server.
    :param port: the port number which the server should run on
    :return:
    """
    # load config file for DH and username/password
    global crypto_service, password_hash_dict, chatting_service, user_addr_dict, auth_dict
    g = c.DH_GENERATOR
    p = util.load_df_param_from_file(c.DH_CONFIG_PATH)
    crypto_service = CryptoService(rsa_pri_path=c.PRI_KEY_PATH, p=p, g=g)
    chatting_service = ChattingService(user_addr_dict, auth_dict, crypto_service)
    password_hash_dict = util.load_pickle_file(c.PW_HASH_PATH)
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        print('Binding to ip: {}'.format(local_ip))
        serv_addr = (local_ip, port)
        serv = SocketServer.UDPServer(serv_addr, ClientRequestHandler)
        # dump the server address to config file for client using
        util.save(c.SERVER_CONFIG_PATH, serv_addr, True)
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
    parser = argparse.ArgumentParser()
    parser.add_argument('-sp', metavar='<ServerPORT>', required=True, type=int, help="specify server port number.")
    opts = parser.parse_args()
    run_server(opts.sp)
    # run_server(9090)
