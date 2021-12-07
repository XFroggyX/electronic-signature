import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import os

from Cryptodome.Hash import SHA512
from Cryptodome.PublicKey import DSA
from Cryptodome.Signature import pkcs1_15


def check_sign(file_public_key, file_signature, file_in, type_hash):
    if type_hash == "RSA256":
        h = SHA256.new()
    else:
        h = SHA512.new()

    with open(file_in, "rb") as f_text:
        while text := f_text.read(4096):
            h.update(text)

    with open(file_public_key) as f:
        key = f.read()

    pub_key = RSA.importKey(key)

    with open(file_signature, "rb") as f_text:
        signature = f_text.read()

    is_verify = pkcs1_15.new(pub_key).verify(h, base64.b64decode(signature))

    return 'True' if is_verify is None else "False"


class EDS:
    def __init__(self, type):
        self.master_private_pem = None
        self.master_public_pem = None
        self.signature = None
        self.key = None
        self.hh = None
        self.type = type

    def gen_key(self) -> None:
        method = self.type[0:3]
        match method:
            case "RSA":
                self.key = RSA.generate(1024, os.urandom)
            case "DSA":
                self.key = DSA.generate(512, os.urandom)

    def generate_master_pem(self) -> None:
        # Генерайия ключей мастера
        self.master_private_pem = self.key.exportKey()
        self.master_public_pem = self.key.publickey().exportKey()

    def save_master_private_pem(self, file_name: str) -> None:
        with open(file_name, 'wb') as f:
            f.write(self.master_private_pem)

    def save_master_public_pem(self, file_name: str) -> None:
        with open(file_name, 'wb') as f:
            f.write(self.master_public_pem)

    def save_key(self, file_name) -> None:
        with open(file_name, 'wb') as f:
            f.write(self.key)

    def sign_file(self, file_in, file_out):
        if self.type == "RSA256":
            h = SHA256.new()
        else:
            h = SHA512.new()

        with open(file_in, "rb") as f_text:
            while text := f_text.read(4096):
                h.update(text)

        # Подписываете хэш
        sign = pkcs1_15.new(self.key).sign(h)
        self.signature = base64.b64encode(sign)
        with open(file_out, "wb") as f_text:
            f_text.write(self.signature)
        #print(self.signature)


"""
'alice-public.pem'
'alice-private.pem'
'bob-public.pem'
'bob-private.pem'
"""
if __name__ == "__main__":
    # Генерация
    eds = EDS("RSA512")
    eds.gen_key()
    eds.generate_master_pem()
    eds.save_master_public_pem('alice-public.pem')
    eds.save_master_private_pem('alice-private.pem')

    # Подпись
    eds.sign_file('urandom_test', 'urand')

    # Проверка
    print(check_sign('alice-public.pem', 'urand', 'urandom_test', 'RSA512'))
