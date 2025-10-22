# device_secure.py
# Dispositivo que fuerza primer arranque, guarda hash de contraseña y usa secure_store.
import hashlib, json, pathlib, time
from getpass import getpass

STATE_FILE = pathlib.Path("device_state.json")

def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()

def first_boot_flow():
    print("=== FIRST BOOT FLOW ===")
    print("Se detecta primer arranque. Debe establecerse nueva contraseña de administrador.")
    # En Colab no usamos getpass interactivo seguro, pero lo simulamos pidiendo input.
    pwd = input("Introduce nueva contraseña admin (mínimo 8 chars): ").strip()
    while len(pwd) < 8:
        pwd = input("Contraseña demasiado corta. Introduce >=8 chars: ").strip()
    pwd_hash = sha256_hex(pwd)
    # Guardar estado básico (no es secure element real)
    state = {
        "firmware": "v2.0-secure",
        "credentials": {"user": "admin", "pass_hash": pwd_hash},
        "ota_version": "1.0"
    }
    STATE_FILE.write_text(json.dumps(state))
    print("Contraseña establecida y guardada como hash.")
    return state

def normal_boot():
    print("=== DEVICE SECURE NORMAL BOOT ===")
    if not STATE_FILE.exists():
        return first_boot_flow()
    state = json.loads(STATE_FILE.read_text())
    print("Boot con firmware:", state.get("firmware"))
    return state

def verify_login(username, password, state):
    if username != state['credentials']['user']:
        return False
    return sha256_hex(password) == state['credentials']['pass_hash']

if __name__ == '__main__':
    state = normal_boot()
    # Test login
    print("Prueba de login con admin/admin (debería fallar si primer arranque fue ejecutado):")
    print("Resultado:", verify_login("admin","admin", state))
