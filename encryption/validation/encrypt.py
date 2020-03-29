import base64
import os
import sys
import cryptography


if len(sys.argv) < 3:
    print('usage: %s plaintext-file encrypt-file' % sys.argv[0])
    exit(0)
input_file = sys.argv[1]
output_file = sys.argv[2]
with open(input_file, 'rb') as f:
    data = f.read()


"""
symmetric keys
"""
from cryptography.fernet import Fernet
kfile='key.key'
if not os.path.exists(kfile):
    key = Fernet.generate_key()
    file = open(kfile, 'wb')
    file.write(key) # The key is type bytes still
    file.close()
else:
    file = open(kfile, 'rb')
    key = file.read() # The key will be type bytes
    file.close()

f = Fernet(key)
encrypted = f.encrypt(bytes(data))
# print(encrypted)

with open(output_file, 'wb') as f:
    f.write(bytes(encrypted))
    print('%s -> %s' % (input_file, output_file))

exit(0)

"""
TODO: asymmetric keys
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

if os.path.exists('private_key.pem') and os.path.exists('public_key.pem'):
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
else:
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend = default_backend()
    )
    public_key = private_key.public_key()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open('private_key.pem', 'wb') as f:
        f.write(pem)

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('public_key.pem', 'wb') as f:
        f.write(pem)

encrypted = public_key.encrypt(
    data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(encrypted)
