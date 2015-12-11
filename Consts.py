GREETING = 'HELLO'
AUTH_SUCCESS = 'SUCCESS'
MSG_HEAD = '#*'
PROMPT = '+> '
USERNAME = 'Username: '
PASSWORD = 'Password: '
WRONG_PASSWORD = 'Wrong password!'
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
P_TEXT_LEN_4096 = 470
C_TEXT_LEN_4096 = 512
SIGN_LEN = 512

DH_PRIME_SIZE = 2048
DH_KEY_SIZE = 512
DH_GENERATOR = 2


SYM_KEY_LENGTH = 32
IV_LENGTH = 16
RSA_KEY_SIZE = 2048
PUBLIC_EXP = 65537
RSA_SIGN_LENGTH = 512
ENC_SYM_KEY_LENGTH = 256
# HEADER_LENGTH = IV_LENGTH + RSA_SIGN_LENGTH + ENC_SYM_KEY_LENGTH
HEADER_LENGTH = IV_LENGTH

MSG_TYPE_KEEP_ALIVE = "KEEP-ALIVE"
MSG_TYPE_LIST = "LIST"
MSG_TYPE_START_NEW_CHAT = "CHAT"
MSG_TYPE_LOGOUT = "LOGOUT"
MSG_TYPE_MSG = "MESSAGE"
MSG_TYPE_PUB_KEY = "PUB_KEY"

MSG_RESPONSE_WRONG_PW = "WPW"
MSG_RESPONSE_OK = "OK"

USR_CMD_LIST = "list"
USR_CMD_CHAT = "send"
USR_CMD_LOGOUT = "logout"
USR_CMD_RE = "((?P<list>" + USR_CMD_LIST + ")|(?P<logout>" + USR_CMD_LOGOUT + ")|((?P<chat>" + USR_CMD_CHAT + ") (?P<username>[a-zA-Z0-9]+) (?P<msg>.+)))"

# header: HAS_NONCE, HAS_TS, END_OF_FIRST_PART, END_OF_SECOND_PART
HEADER_LEN = 12
PKT_HEADER_RE = "(?P<has_ts>\d)(?P<has_nonce>\d)(?P<eofp>\d{5})(?P<eosp>\d{5})"
TRUE_STR = "1"
FALSE_STR = "0"
NONCE_LEN = 8
TS_LEN = 26
ERR_CMD = "Command not right. Use LIST or [CHAT <username> <msg>]"
ERR_CMD_CHAT = "Chat command invalid."
ERR_CMD_NO_USER = "Username doesn't exist!"


CACHE_TYPE_IND = 0
CACHE_KEY_IND = 1
CACHE_MSG_IND = 2
CACHE_ADDR_IND = 3
CACHE_TS_IND = 4
CACHE_AUTH_IND = 5

TS_VALID_MICRO_SEC = 100000
TS_RESEND_MICRO_SEC = 1000000
RESEND_SLEEP_SEC = 2

HMAC_LEN = 32