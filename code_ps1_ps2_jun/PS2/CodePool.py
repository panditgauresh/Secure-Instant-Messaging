import argparse
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import os



###################################
#
###################################

# asym_key(sym_key + digest_key + digest of cipher) + cipher_test


def main():
    # TODO load key files
    asym_key = b"a key"

    # TODO load input file
    plain_text = b"plain text"

    # TODO pad the plain text
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(b"text")
    padded_data += padder.finalize()


    # TODO unpad the text after receiving
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(padded_data)
    unpadded_data += unpadder.finalize()

    # generate signature with HMAC
    key = os.urandom(32)
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(b"data")
    sign = h.finalize()

    # verify data with HMAC
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(b"data")
    h.verify(sign)

    # generate cipher text
    sym_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plain_text) + encryptor.finalize()



    # decrypt the cipher text
    cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    d_plain_text = decryptor(cipher_text) + decryptor.finalize()










if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('dest_key', help='Destination Public/Private key')
    parser.add_argument('sender_key', help='Sender Private/Public key')
    parser.add_argument('input', help='Input file')
    parser.add_argument('output', help='Output file')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', action='store_true')
    group.add_argument('-d', action='store_true')
    opts = parser.parse_args()
    print opts

    # run_client(opts.sip, opts.sp)