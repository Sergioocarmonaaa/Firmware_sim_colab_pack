# device_insecure.py
# Simulación de firmware inseguro (muestra credenciales en texto claro)
import time

def run_device():
    print("=== DEVICE v1.0 (INSEGURO) ===")
    print("Inicio del dispositivo...")
    print("Credentials: admin / admin")
    print("Wi-Fi: SSID=MiRed PASS=12345678")
    print("Servicio web activo en puerto 80")
    # Simula envio de datos (texto claro)
    for i in range(3):
        print(f"Sending sensor reading -> temperature={25 + i*0.5:.2f} C")
        time.sleep(0.5)

if __name__ == '__main__':
    run_device()
