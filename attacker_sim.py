# attacker_sim.py
# Simula a un atacante que usa credenciales por defecto para "conectarse" al dispositivo.
import time, sys

def try_login(username, password, target_credentials):
    print("=== ATTACKER SIMULATION ===")
    print(f"Intentando login con {username}/{password} ...")
    time.sleep(0.5)
    if username == target_credentials['user'] and password == target_credentials['pass']:
        print("LOGIN OK -> Acceso concedido (simulado).")
        print("Posibles acciones del atacante: cambiar config, extraer datos, instalar backdoor.")
        return True
    else:
        print("LOGIN FAILED -> credenciales incorrectas.")
        return False

if __name__ == '__main__':
    # recibe target creds vía fichero JSON
    import json, pathlib
    cfg_path = pathlib.Path("device_state.json")
    if not cfg_path.exists():
        print("device_state.json no encontrado. Ejecuta primero la simulación del dispositivo.")
        sys.exit(1)
    cfg = json.loads(cfg_path.read_text())
    # atacante prueba con admin/admin
    try_login("admin","admin", cfg['credentials'])
