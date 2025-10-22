# attacker_after.py
# Attacker tries login after secure flow
import json, pathlib
STATE = pathlib.Path("device_state.json")
if not STATE.exists():
    print("No device state found. Ejecuta device_secure first.")
else:
    st = json.loads(STATE.read_text())
    # Attacker tries admin/admin
    from device_secure import verify_login
    ok = verify_login("admin","admin", st)
    print("Attack with admin/admin -->", "SUCCESS" if ok else "FAIL (expected)")
