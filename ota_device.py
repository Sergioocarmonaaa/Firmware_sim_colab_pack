# ota_device.py
# Simulación de la verificación OTA en el dispositivo (usa la public key para verificar la firma)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import pathlib, json

PRIV = pathlib.Path("ota_private.pem")
PUB = pathlib.Path("ota_public.pem")
IMAGE = pathlib.Path("firmware_image.bin")
SIG = pathlib.Path("firmware.sig")
STATE = pathlib.Path("device_state.json")

def verify_and_apply():
    if not PUB.exists() or not IMAGE.exists() or not SIG.exists():
        print("Faltan archivos (pub/image/sig). Ejecuta ota_sign.py primero.")
        return
    pub = serialization.load_pem_public_key(PUB.read_bytes())
    try:
        pub.verify(SIG.read_bytes(), IMAGE.read_bytes(),
                   padding.PKCS1v15(), hashes.SHA256())
        print("VERIFICACION OK: la imagen está firmada por el proveedor.")
        # Simula aplicar update: actualizar campo ota_version
        if STATE.exists():
            st = json.loads(STATE.read_text())
        else:
            st = {"firmware":"v2.0-secure","credentials":{}}
        st['ota_version'] = "1.1"
        STATE.write_text(json.dumps(st))
        print("OTA aplicada. Nueva ota_version = 1.1 (simulado).")
    except Exception as e:
        print("VERIFICACION FALLIDA:", e)

if __name__ == '__main__':
    verify_and_apply()
