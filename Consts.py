GREETING = 'HELLO'
AUTH_SUCCESS = 'SUCCESS'
MSG_HEAD = '#*'
PROMPT = '+> '
USERNAME = 'Username: '
PASSWORD = 'Password: '
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
DH_CONFIG_PATH = "config/dh_param"
PW_HASH_PATH = "config/pw_hash_dict"
SERVER_CONFIG_PATH = "config/server_addr"
P_TEXT_LEN_4096 = 470
C_TEXT_LEN_4096 = 512
SIGN_LEN = 512

DH_PRIME_SIZE = 2048
DH_KEY_SIZE = 512
DH_GENERATOR = 2


SYM_KEY_LENGTH = 32
IV_LENGTH = 16
RSA_KEY_SIZE = 2048
RSA_PUB_KEY_EXT = ".pub"
PUBLIC_EXP = 65537
RSA_SIGN_LENGTH = 512
ENC_SYM_KEY_LENGTH = 256
# HEADER_LENGTH = IV_LENGTH + RSA_SIGN_LENGTH + ENC_SYM_KEY_LENGTH
HEADER_LENGTH = IV_LENGTH
SOCK_BUFFER = 20480

MSG_TYPE_KEEP_ALIVE = "KEEP-ALIVE"
MSG_TYPE_LIST = "LIST"
MSG_TYPE_START_NEW_CHAT = "CHAT"
MSG_TYPE_LOGOUT = "LOGOUT"
MSG_TYPE_MSG = "MESSAGE"
MSG_TYPE_PUB_KEY = "PUB_KEY"

MSG_RESPONSE_WRONG_CR = "WCR"
MSG_RESPONSE_USER_EXISTS = "UE"
MSG_RESPONSE_OK = "OK"

USER_LIST_START = "\rOnline users:\n"
SUCCESS_LOGIN_MSG = "Login success!"
WRONG_CR_MSG = "Wrong username/password pair!"
USER_ALREADY_LOGIN_MSG = "User logined on other client!"
STEP_ONE_FAIL_MSG = "Step 1 signature verification fail."
STEP_THREE_NONCE_FAIL_MSG = "Step 3 nonce failed."
PACKET_CORRUPTED_MSG = "Packet corrupted"
TS_INVALID_MSG = "Timestamp invalid: "

USR_CMD_LIST = "list"
USR_CMD_CHAT = "send"
USR_CMD_LOGOUT = "logout"
USR_CMD_RE = "((?P<list>" + USR_CMD_LIST + ")|(?P<logout>" + USR_CMD_LOGOUT + ")|((?P<chat>" + USR_CMD_CHAT + ") (?P<username>[a-zA-Z0-9]+) (?P<msg>.+)))"
USR_CMD_RE_GROUP_USER = "username"
USR_CMD_RE_GROUP_MSG = "msg"

# header: HAS_NONCE, HAS_TS, END_OF_FIRST_PART, END_OF_SECOND_PART
HEADER_LEN = 12
PKT_HEADER_RE = "(?P<has_ts>\d)(?P<has_nonce>\d)(?P<eofp>\d{5})(?P<eosp>\d{5})"
TRUE_STR = "1"
FALSE_STR = "0"
NONCE_LEN = 8
TS_LEN = 26
TS_FORMAT = "%m:%d:%Y:%H:%M:%S:%f"
ERR_CMD = "Command not right. Use LIST or [CHAT <username> <msg>]"
ERR_CMD_CHAT = "Chat command invalid."
ERR_CMD_NO_USER = "Username doesn't exist!"
ERR_CLIENT_DOWN = "Client is offline."

WARNING_STOP_RESENDING = "Stop message resending."
WARNING_TTB_INVALID = "Ticket To B corrupted!"
WARNING_TTB_USERNAME_INVALID = "Username not match in the TTB!"
WARNING_EXISTED_NONCE = "Nonce existed in cache!"

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
KEEP_ALIVE_TIME = 75
CHL_NUM = 20000
CHL_BYTE_LEN = 3
CHL_ENCODE = 'utf-8'

AUTH_STAGE_INIT = 0
AUTH_STAGE_1 = 1
AUTH_STAGE_2 = 2
AUTH_STAGE_FINISHED = 3