from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class PrivateKeyUtil():
    key = None

    def __init__(self, key_path):
        # load key
        with open(key_path, "rb") as key_file:
            self.key = serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())


    @staticmethod
    def generate_keys(key_path, key_size=2048, pub_exp=65537):
        # rsa key generation
        private_key = rsa.generate_private_key(public_exponent=pub_exp, key_size=key_size, backend=default_backend())
        # private key serialization
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=serialization.NoEncryption())
        with open(key_path, "wb+") as key_file:
            key_file.write(pem)

        # public key serialization
        public_key = private_key.public_key()
        pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(key_path + ".pub", "wb+") as key_file:
            key_file.write(pem)

        return (private_key, public_key)


    def sign(self, message):
        # sign message
        signer = self.key.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                             salt_length=padding.PSS.MAX_LENGTH),
                                 hashes.SHA256())
        signer.update(message)
        return signer.finalize()


    def decrypt(self, c_text):
        # decrypt header
        tmp1 = len(c_text)
        p_text = self.key.decrypt(c_text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                           algorithm=hashes.SHA1(),
                                                           label=None))
        return p_text


class PublicKeyUtil():
    key = None

    def __init__(self, key_path):
        with open(key_path, "rb") as key_file:
            self.key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
        # isinstance(self.key, rsa.RSAPublicKey)


    def encrypt(self, p_text):
        # encrypt header with rsa
        c_text = self.key.encrypt(p_text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                           algorithm=hashes.SHA1(),
                                                           label=None))
        return c_text


    def verify(self, message, signature):
        # verify signature
        verifier = self.key.verifier(signature,
                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                     hashes.SHA256())
        verifier.update(message)
        try:
            verifier.verify()
        except InvalidSignature:
            return False
        return True


if __name__ == '__main__':
    # PrivateKeyUtil.generate_keys('keys/key_sender')
    # PrivateKeyUtil.generate_keys('keys/key_server', key_size=4096)
    pk_path = "keys/key_server.pub"
    pku = PublicKeyUtil(pk_path)
    msg = "123,joncai,456"
    enc_msg = pku.encrypt(msg)
    print(enc_msg)
