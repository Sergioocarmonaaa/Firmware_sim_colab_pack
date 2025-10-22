# ota_sign.py
# Genera RSA keypair y firma un "firmware image" (archivo simple).
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import pathlib

PRIV = pathlib.Path("ota_private.pem")
PUB = pathlib.Path("ota_public.pem")
IMAGE = pathlib.Path("firmware_image.bin")
SIG = pathlib.Path("firmware.sig")

def gen_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    PRIV.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    PUB.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    print("Claves RSA generadas.")

def create_image():
    data = b"This is a simulated firmware binary v1.1"
    IMAGE.write_bytes(data)
    print("Imagen firmware creada.")

def sign_image():
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_private_key(PRIV.read_bytes(), password=None)
    signature = key.sign(IMAGE.read_bytes(),
                         padding.PKCS1v15(),
                         hashes.SHA256())
    SIG.write_bytes(signature)
    print("Firma creada:", SIG)

if __name__ == '__main__':
    gen_keys()
    create_image()
    sign_image()
