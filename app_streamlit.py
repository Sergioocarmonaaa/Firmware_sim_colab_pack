# app_streamlit.py — Streamlit UI for the secure IoT simulation
import streamlit as st
import json, hmac, hashlib, secrets, time
from pathlib import Path
from datetime import datetime

STATE_PATH = Path("device_state.json")
AUDIT_LOG = Path("device_audit.log")

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
    if not STATE_PATH.exists():
        state = {
            "first_boot": True,
            "users": {},
            "key_value": None,
            "baud": BAUD,
            "fw_version": FW_VERSION,
            "ota_key_version": 1
        }
        STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")
        log_event("STATE init: first_boot=True")

def load_state() -> dict:
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))

def save_state(state: dict):
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")

def read_temp():
    t = 24.0 + (time.time() * 1000 % 1000) / 100.0
    return round(t, 2)

def status(state: dict, authenticated: bool):
    return f"OK;FW={state['fw_version']};BAUD={state['baud']};AUTH={'yes' if authenticated else 'no'}"

def verify_ota_signature_bytes(data: bytes, sig_hex: str) -> bool:
    calc = hmac.new(OTA_HMAC_KEY, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc, sig_hex.strip())

st.set_page_config(page_title="IoT Secure UART Demo", page_icon="🔒")
st.title("🔒 IoT Secure UART Demo — Streamlit")

init_state()
state = load_state()

if "user" not in st.session_state:
    st.session_state.user = None

if state.get("first_boot", True):
    st.subheader("Primer arranque seguro")
    st.info("No hay contraseña por defecto. Crea las credenciales de administrador para continuar.")
    with st.form("first_boot_form", clear_on_submit=False):
        pw1 = st.text_input("Nueva contraseña de admin", type="password")
        pw2 = st.text_input("Repite la contraseña", type="password")
        submitted = st.form_submit_button("Inicializar")
        if submitted:
            if pw1 != pw2:
                st.error("Las contraseñas no coinciden.")
            elif len(pw1) < 10 or pw1.islower() or pw1.isalpha():
                st.error("Política: mínimo 10 caracteres y mezcla de tipos (may/min/dígitos/símbolos).")
            else:
                state["users"]["admin"] = pbkdf2_hash(pw1)
                state["first_boot"] = False
                state["key_value"] = "PROV-" + secrets.token_hex(4)
                save_state(state)
                log_event("First-boot: admin password set")
                st.success("Sistema inicializado. Recarga la página o inicia sesión en la barra lateral.")
else:
    with st.sidebar:
        st.header("Acceso")
        if st.session_state.user:
            st.success(f"Conectado como **{st.session_state.user}**")
            if st.button("Cerrar sesión"):
                st.session_state.user = None
        else:
            with st.form("login_form"):
                user = st.text_input("Usuario", value="admin")
                pw = st.text_input("Contraseña", type="password")
                go = st.form_submit_button("Entrar")
                if go:
                    if user not in state["users"]:
                        st.error("Usuario desconocido.")
                        log_event(f"Auth fail: unknown user '{user}'")
                    elif verify_password(state["users"][user], pw):
                        st.session_state.user = user
                        log_event(f"Auth ok: {user}")
                        st.experimental_rerun()
                    else:
                        st.error("LOGIN FAIL")
                        log_event(f"Auth fail: {user}")

    st.subheader("Estado del dispositivo")
    st.code(status(state, st.session_state.user is not None))

    st.subheader("Sensores")
    if st.button("READ TEMP"):
        st.write(f"🌡️ Temperatura: **{read_temp()} °C**")

    st.subheader("Configuración protegida")
    if st.session_state.user:
        with st.form("set_key_form"):
            key_val = st.text_input("Nuevo valor de KEY (no se mostrará en claro)")
            submit_key = st.form_submit_button("SET KEY")
            if submit_key:
                import hashlib
                state["key_value"] = f"SECURE-{hashlib.sha1(key_val.encode()).hexdigest()[:6]}"
                save_state(state)
                log_event(f"KEY updated by {st.session_state.user}")
                st.success("KEY actualizada (valor no mostrable).")
        with st.form("change_pass_form"):
            st.write("Cambiar contraseña")
            npw1 = st.text_input("Nueva contraseña", type="password")
            npw2 = st.text_input("Repite contraseña", type="password")
            ch = st.form_submit_button("Cambiar")
            if ch:
                if npw1 != npw2:
                    st.error("No coinciden.")
                elif len(npw1) < 10 or npw1.islower() or npw1.isalpha():
                    st.error("Política: mínimo 10 caracteres y mezcla de tipos.")
                else:
                    state["users"][st.session_state.user] = pbkdf2_hash(npw1)
                    save_state(state)
                    log_event(f"Password changed for {st.session_state.user}")
                    st.success("Contraseña actualizada.")
    else:
        st.warning("Inicia sesión para modificar configuración.")

    st.subheader("OTA verificación (HMAC-SHA256)")
    fw = st.file_uploader("Firmware (.bin)", type=None, key="fw")
    sig = st.file_uploader("Firma (.sig)", type=["sig", "txt"], key="sig")
    if st.button("Verificar OTA") and fw and sig:
        fw_bytes = fw.read()
        sig_hex = sig.read().decode("utf-8")
        ok = verify_ota_signature_bytes(fw_bytes, sig_hex)
        if ok:
            st.success("OTA SIGNATURE: OK")
            log_event("OTA verify via UI -> OK")
        else:
            st.error("OTA SIGNATURE: FAIL")
            log_event("OTA verify via UI -> FAIL")

st.caption("Demo académica: no reutilizar claves en producción. Use secure elements/TPM y gestión de secretos adecuada.")
