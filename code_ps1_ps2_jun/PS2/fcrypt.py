import argparse
from Encryptor import Encryptor
from Decryptor import Decryptor


###################################
#       message structure         #
###################################
# encrypted_sym_key + cbc_iv + signature + cipher_text

def main(dest_key_path, sender_key_path, input_path, output_path, is_encrypt=True):

    if is_encrypt:
        # for encrypting a file
        with open(input_path, "rb") as mail_file:
            p_text = mail_file.read()

        en = Encryptor(dest_key_path, sender_key_path)
        c_text = en.encrypt(p_text)

        with open(output_path, "wb+") as c_mail_file:
            c_mail_file.write(c_text)
    else:
        # for decrypting a file
        with open(input_path, "rb") as c_mail_file:
            c_text = c_mail_file.read()

        dec = Decryptor(dest_key_path, sender_key_path)
        p_text = dec.decrypt(c_text)

        with open(output_path, "wb+") as p_mail_file:
            p_mail_file.write(p_text)

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
    main(opts.dest_key, opts.sender_key, opts.input, opts.output, opts.e)
