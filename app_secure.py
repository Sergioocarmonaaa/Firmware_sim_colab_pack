#!/usr/bin/env python3
"""
app_secure.py — Simulación de dispositivo IoT "seguro" para la práctica S7

Características implementadas (según guía de la actividad):
- Primer arranque seguro: NO hay contraseña por defecto. Obliga a crearla.
- Almacenamiento seguro: password con hash PBKDF2-HMAC-SHA256 + salt y múltiples iteraciones.
- UART/Consola: sin comandos de volcado de secretos (no existe "DUMP SECRETS").
- Autenticación obligatoria para comandos sensibles.
- OTA "firmada": verificación de firma HMAC-SHA256 sobre firmware.bin con clave simétrica embebida.
  (sin dependencias externas). Se usa un archivo de firma .sig con el digest hex.
- Registro simple de auditoría en device_audit.log

Uso:
  python app_secure.py               # Modo interactivo (simula UART/terminal)
  python app_secure.py --verify-ota firmware.bin firmware.sig  # Verifica firma OTA y sale

Requisitos: Python 3.8+ (solo librerías estándar)
"""

import os, sys, json, time, hmac, hashlib, secrets, getpass, random
from pathlib import Path
from datetime import datetime

STATE_PATH = Path("device_state.json")
AUDIT_LOG = Path("device_audit.log")

# Clave simétrica para HMAC (OTA). En producción se usaría un secure element o key provisioning.
# Esta clave se puede rotar cambiando la versión. Aquí está codificada para la práctica.
OTA_HMAC_KEY = bytes.fromhex("b55b77b8d6f33a4c911d8b3a1f5f7d0d3c6a5e4f2a1b0c9d8e7f6a5b4c3d2e1f")

FW_VERSION = "1.1-secure"
BAUD = 115200

def log_event(event: str):
    ts = datetime.utcnow().isoformat() + "Z"
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(f"{ts} {event}\n")

def pbkdf2_hash(password: str, salt: bytes = None, iters: int = 200_000):
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=32)
    return {
        "algo": "PBKDF2-HMAC-SHA256",
        "iterations": iters,
        "salt_hex": salt.hex(),
        "hash_hex": dk.hex(),
    }

def verify_password(stored: dict, password: str) -> bool:
    salt = bytes.fromhex(stored["salt_hex"])
    iters = int(stored["iterations"])
    expected = bytes.fromhex(stored["hash_hex"])
    calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=32)
    return hmac.compare_digest(calc, expected)

def init_state():
    # Si no existe el estado, iniciamos en "primer arranque"
    if not STATE_PATH.exists():
        state = {
            "first_boot": True,
            "users": {},           # "admin": {hash...}
            "key_value": None,     # No se expone nunca en texto claro por comandos
            "baud": BAUD,
            "fw_version": FW_VERSION,
            "ota_key_version": 1
        }
        STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")
        log_event("STATE init: first_boot=True")
    else:
        try:
            json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            # Rescate: si el JSON está corrupto, no continuamos en inseguro
            raise SystemExit("Estado corrupto. Borra device_state.json manualmente para reinicializar (perderás credenciales).")

def save_state(state: dict):
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")

def load_state() -> dict:
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))

def first_boot_setup():
    state = load_state()
    if not state["first_boot"]:
        return
    print("== Primer arranque seguro ==")
    print("No hay contraseña por defecto. Debe crear credenciales de administrador para continuar.\n")
    while True:
        user = "admin"
        pw1 = getpass.getpass("Nueva contraseña para admin: ")
        pw2 = getpass.getpass("Repite la contraseña: ")
        if pw1 != pw2:
            print("Las contraseñas no coinciden.\n")
            continue
        if len(pw1) < 10 or pw1.islower() or pw1.isalpha():
            print("Política: mínimo 10 caracteres, mezcla de tipos (may/min/dígitos/símbolos). Intenta de nuevo.\n")
            continue
        state["users"][user] = pbkdf2_hash(pw1)
        state["first_boot"] = False
        state["key_value"] = "PROV-" + secrets.token_hex(4)  # clave inicial no sensible
        save_state(state)
        log_event("First-boot: admin password set")
        print("Credenciales establecidas. Sistema seguro inicializado.\n")
        break

def human_help(authenticated: bool):
    print("Comandos disponibles:")
    print("  HELP                - mostrar esta ayuda")
    print("  STATUS              - versión y parámetros (no secretos)")
    print("  READ TEMP           - leer temperatura simulada")
    print("  LOGIN               - iniciar sesión")
    print("  LOGOUT              - cerrar sesión")
    print("  OTA VERIFY <bin> <sig> - verificar firma HMAC de firmware")
    if authenticated:
        print("  CHANGE PASS         - cambiar contraseña del usuario actual")
        print("  SET KEY <valor>     - establecer valor de configuración (no se muestra nunca)")
    print("  EXIT                - salir")

def read_temp():
    # Temperatura simulada 24.00..33.99
    t = 24.0 + (time.time() * 1000 % 1000) / 100.0
    return round(t, 2)

def status(state: dict, authenticated: bool):
    line = f"OK;FW={state['fw_version']};BAUD={state['baud']};AUTH={'yes' if authenticated else 'no'}"
    print(line)

def login(state: dict):
    user = input("Usuario: ").strip() or "admin"
    if user not in state["users"]:
        print("Usuario desconocido.")
        log_event(f"Auth fail: unknown user '{user}'")
        return None
    pw = getpass.getpass("Contraseña: ")
    if verify_password(state["users"][user], pw):
        print("LOGIN OK")
        log_event(f"Auth ok: {user}")
        return user
    print("LOGIN FAIL")
    log_event(f"Auth fail: {user}")
    return None

def change_pass(state: dict, user: str):
    pw1 = getpass.getpass("Nueva contraseña: ")
    pw2 = getpass.getpass("Repite la contraseña: ")
    if pw1 != pw2:
        print("No coinciden.")
        return
    if len(pw1) < 10 or pw1.islower() or pw1.isalpha():
        print("Política: mínimo 10 chars y mezcla de tipos.")
        return
    state["users"][user] = pbkdf2_hash(pw1)
    save_state(state)
    print("Contraseña actualizada.")
    log_event(f"Password changed for {user}")

def set_key(state: dict, user: str, value: str):
    # No se muestra ni registra el valor. Solo se confirma la operación.
    state["key_value"] = f"SECURE-{hashlib.sha1(value.encode()).hexdigest()[:6]}"  # registrar derivado no reversible
    save_state(state)
    print("KEY actualizada.")
    log_event(f"KEY updated by {user}")

def verify_ota_signature(bin_path: str, sig_path: str) -> bool:
    try:
        data = Path(bin_path).read_bytes()
        sig_hex = Path(sig_path).read_text(encoding="utf-8").strip()
        calc = hmac.new(OTA_HMAC_KEY, data, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(calc, sig_hex)
        return ok
    except FileNotFoundError as e:
        print(f"No se encuentra archivo: {e}")
        return False
    except Exception as e:
        print(f"Error verificando OTA: {e}")
        return False

def cli():
    init_state()
    first_boot_setup()
    state = load_state()

    print("UART demo (modo seguro) - ESP32 simulado")
    print("Tip: escribe HELP")
    authenticated_user = None

    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nEXIT")
            break

        if not line:
            continue

        cmd = line.upper().split()
        if cmd[0] == "HELP":
            human_help(authenticated_user is not None)
        elif cmd[0] == "STATUS":
            status(state, authenticated_user is not None)
        elif cmd[0] == "READ" and len(cmd) > 1 and cmd[1] == "TEMP":
            print(f"{read_temp()} C")
        elif cmd[0] == "LOGIN":
            authenticated_user = login(state)
        elif cmd[0] == "LOGOUT":
            authenticated_user = None
            print("Sesión cerrada.")
        elif cmd[0] == "CHANGE" and len(cmd) > 1 and cmd[1] == "PASS":
            if not authenticated_user:
                print("Requiere autenticación.")
            else:
                change_pass(state, authenticated_user)
                state = load_state()
        elif cmd[0] == "SET" and len(cmd) > 2 and cmd[1] == "KEY":
            if not authenticated_user:
                print("Requiere autenticación.")
            else:
                # valor original respetando mayúsculas/minúsculas a partir de la línea
                value = line.split("KEY",1)[1].strip().lstrip("=").strip()
                if not value:
                    print("Uso: SET KEY=<valor>")
                else:
                    set_key(state, authenticated_user, value)
        elif cmd[0] == "OTA" and len(cmd) > 1 and cmd[1] == "VERIFY":
            parts = line.split()
            if len(parts) != 4:
                print("Uso: OTA VERIFY <firmware.bin> <firmware.sig>")
            else:
                ok = verify_ota_signature(parts[2], parts[3])
                print("OTA SIGNATURE: OK" if ok else "OTA SIGNATURE: FAIL")
                log_event(f"OTA verify {parts[2]} -> {'OK' if ok else 'FAIL'}")
        elif cmd[0] == "EXIT":
            break
        else:
            print("ERR: comando desconocido")
            print("Escribe HELP")
    print("Bye.")

if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--verify-ota":
        ok = verify_ota_signature(sys.argv[2], sys.argv[3])
        print("OTA SIGNATURE:", "OK" if ok else "FAIL")
        sys.exit(0 if ok else 1)
    cli()
