# python ChatClient.py -sip 192.168.1.9 -sp 9090 -cp 9091

pub_path = 'keys/key_server.pub'
# with open(pub_path, "r") as f:
#     f.readline()
#     pub_str = f.read().replace('\n', '')
# print(pub_str.encode('hex'))
#
# pri_path = 'keys/key_server_copy'
# with open(pri_path, "r") as f:
#     f.readline()
#     pri_str = f.read().replace('\n', '')
# print(pri_str.encode('hex'))

from KeyUtil import PublicKeyUtil, PrivateKeyUtil
p_text = "123,192.168.1.175:55056,345"
pub = PublicKeyUtil(pub_path)
en_text = pub.encrypt(p_text)
print(en_text)