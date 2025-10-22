README — Proyecto Colab: Firmware vulnerable y remediación (simulado)

Archivos creados:
 - device_insecure.py   : firmware v1 inseguro (muestra credenciales en texto plano)
 - attacker_sim.py      : atacante que prueba admin/admin contra device_state.json
 - device_secure.py     : firmware v2 con primer arranque que guarda hash de contraseña
 - secure_store.py      : helper para simular secure element (Fernet)
 - ota_sign.py          : genera keys RSA, crea imagen y firma
 - ota_device.py        : verifica firma y aplica OTA (simulado)
 - attacker_after.py    : atacante que prueba login tras remediación

Guía rápida de ejecución (ejemplos para Colab):
1) Ejecuta device_insecure:
   python3 device_insecure.py

2) Crear device_state.json (simular dispositivo vulnerable):
   python3 - <<'PY'
import json
d = {"firmware":"v1.0","credentials":{"user":"admin","pass":"admin"}}
open('device_state.json','w').write(json.dumps(d))
print('device_state.json creado')
PY

3) Ejecuta attacker_sim.py:
   python3 attacker_sim.py

4) Ejecuta device_secure.py y sigue el primer arranque (establece nueva contraseña).

5) Ejecuta attacker_after.py (debería fallar admin/admin).

6) Ejecuta ota_sign.py y ota_device.py para simular OTA firmado.

Entregables sugeridos:
 - Capturas de ejecución y salidas de los scripts.
 - Documento (máx 250 palabras) con 6 pasos de mitigación.

Notas:
 - Todo simulado y local. No accede a redes externas.
