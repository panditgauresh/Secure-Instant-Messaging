GREETING = 'HELLO'
MSG_HEAD = '#*'
PROMPT = '+> '
TERM_MSG = "Terminating the client ... (press ENTER if it's hanging) "
WELC_MSG = 'ChatClient started. To stop it, press CTRL+C then hit ENTER.'
FWD_MSG = "{}<From {}>: {}"
FAIL_GRE_MSG = 'Failed to send GREETING message.'
FAIL_SEND = 'Failed to send message.'
BYE = 'Bye!'
FAIL_SRV_INIT = 'Failed to initialize server. Maybe the port is in use.'
SRV_START = 'Server Initialized...'
FAIL_SRV_START = 'Failed to start server.'
FAIL_MSG_FWD = 'Failed to forward message.'

PUB_KEY_PATH = 'keys/key_server.pub'
PRI_KEY_PATH = 'keys/key_server'

DH_PRIME_SIZE = 2048
DH_KEY_SIZE = 512
DH_GENERATOR_INDEX = 0

SYM_KEY_LENGTH = 32
IV_LENGTH = 16
RSA_KEY_SIZE = 2048
PUBLIC_EXP = 65537
RSA_SIGN_LENGTH = 256
ENC_SYM_KEY_LENGTH = 256
# HEADER_LENGTH = IV_LENGTH + RSA_SIGN_LENGTH + ENC_SYM_KEY_LENGTH
HEADER_LENGTH = IV_LENGTH
