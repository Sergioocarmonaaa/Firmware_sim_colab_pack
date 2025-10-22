# secure_store.py
# Simulación muy básica de un secure element: cifrado simétrico con Fernet para almacenar secretos.
from cryptography.fernet import Fernet
import json, pathlib

STORE_FILE = pathlib.Path("secure_store.bin")
KEY_FILE = pathlib.Path("secure_key.key")

def init_store():
    # Genera clave y la guarda (simula provisionado hardware)
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    f = Fernet(key)
    # crea store vacío (encoded)
    STORE_FILE.write_bytes(f.encrypt(b"{}"))
    return key

def load_store():
    if not KEY_FILE.exists() or not STORE_FILE.exists():
        return None, None
    key = KEY_FILE.read_bytes()
    f = Fernet(key)
    data = json.loads(f.decrypt(STORE_FILE.read_bytes()).decode())
    return f, data

def save_store(f, data):
    STORE_FILE.write_bytes(f.encrypt(json.dumps(data).encode()))

if __name__ == '__main__':
    print("secure_store helper. Usa sus funciones desde otros scripts.")
