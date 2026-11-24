"""Captura de evidencias reales de los hallazgos OWASP con Selenium.

Requiere el servidor corriendo en modo laboratorio:
    python run.py --lab

Uso:
    python scripts/capturar_evidencias.py --url http://127.0.0.1:5000
    python scripts/capturar_evidencias.py --only-report   # tras generar el informe

Guarda PNG en reports/capturas/ y datos HTTP en reports/evidencias.json.
"""

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests
from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

ROOT = Path(__file__).resolve().parent.parent
SHOTS = ROOT / "reports" / "capturas"
SHOTS.mkdir(parents=True, exist_ok=True)
EVIDENCE_FILE = ROOT / "reports" / "evidencias.json"

XSS_PAYLOAD = """<img src=x onerror="document.getElementById('banner-xss').textContent='XSS EJECUTADO · código del atacante'">"""
SQLI_PAYLOAD = "' OR 1=1 --"


def build_driver() -> webdriver.Chrome:
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--window-size=1440,1000")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--hide-scrollbars")
    return webdriver.Chrome(options=options)


def load_evidence() -> dict:
    if EVIDENCE_FILE.exists():
        return json.loads(EVIDENCE_FILE.read_text(encoding="utf-8"))
    return {
        "titulo": "Evidencias de pruebas de seguridad OWASP",
        "fecha": datetime.now(timezone.utc).isoformat(),
        "metodo": "Selenium (Chrome headless) + peticiones HTTP reproducibles",
        "capturas": [],
        "verificaciones": {},
    }


def save_evidence(data: dict) -> None:
    EVIDENCE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def http_check(method: str, path: str, **kwargs) -> dict:
    try:
        response = requests.request(method, kwargs.pop("base_url", "http://127.0.0.1:5000") + path,
                                    timeout=10, **kwargs)
        return {
            "url": path,
            "metodo": method,
            "codigo": response.status_code,
            "cabeceras": {k: v for k, v in response.headers.items()
                          if k.lower().startswith(("content-security", "x-content", "x-frame",
                                                   "referrer", "permissions", "cache"))},
        }
    except requests.RequestException as exc:
        return {"url": path, "metodo": method, "error": str(exc)}


def http_check_csrf(method: str, path: str, base_url: str, data: dict | None = None) -> dict:
    """Petición con token CSRF válido (sin sesión autenticada)."""
    session = requests.Session()
    session.get(f"{base_url}/login", timeout=10)
    token = session.cookies.get("psw_csrf", "")
    try:
        response = session.request(
            method, f"{base_url}{path}", data=data,
            headers={"X-CSRF-Token": token}, timeout=10, allow_redirects=False,
        )
        return {"url": path, "metodo": method, "codigo": response.status_code,
                "cabeceras": {"Content-Security-Policy": response.headers.get("Content-Security-Policy", "")}}
    except requests.RequestException as exc:
        return {"url": path, "metodo": method, "error": str(exc)}


def run(base_url: str = "http://127.0.0.1:5000", only_report: bool = False) -> dict:
    base_url = base_url.rstrip("/")
    data = load_evidence()
    # Sólo la captura completa regenera el listado; --only-report añade la del informe.
    if not only_report:
        data["capturas"] = []
    driver = build_driver()
    wait = WebDriverWait(driver, 20)

    def shot(filename: str, description: str) -> None:
        driver.save_screenshot(str(SHOTS / filename))
        data["capturas"].append({"archivo": f"capturas/{filename}", "descripcion": description})
        print(f"  [IMG] {filename}: {description}")

    def wait_text(text: str, selector: str = "body") -> None:
        # Chrome a veces devuelve un error de inspector transitorio al leer un nodo
        # que acaba de cambiar; reintentamos dentro del mismo timeout.
        deadline = time.time() + 25
        last_error: Exception | None = None
        while time.time() < deadline:
            try:
                wait.until(EC.text_to_be_present_in_element((By.CSS_SELECTOR, selector), text))
                return
            except WebDriverException as exc:
                last_error = exc
                time.sleep(0.3)
        if last_error is not None:
            raise last_error
        wait.until(EC.text_to_be_present_in_element((By.CSS_SELECTOR, selector), text))

    try:
        if only_report:
            driver.get(f"{base_url}/static/evidencias/informe.html")
            wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".report-title")))
            shot("13_informe_generado.png", "Informe de hallazgos con las capturas incrustadas")
            data["reporte_capturado"] = True
            save_evidence(data)
            return data

        # --- Acceso y navegación -------------------------------------------
        driver.get(f"{base_url}/login")
        wait.until(EC.presence_of_element_located((By.ID, "login-form")))
        shot("01_login.png", "Pantalla de acceso del portal (diseño celeste/azul/blanco)")

        driver.find_element(By.NAME, "username").send_keys("admin")
        driver.find_element(By.NAME, "password").send_keys("Admin123*")
        driver.find_element(By.CSS_SELECTOR, "#login-form button[type=submit]").click()
        wait.until(EC.url_contains("/app"))
        shot("02_dashboard_admin.png", "Panel del administrador con controles de seguridad activos")

        driver.get(f"{base_url}/app/laboratorio")
        wait.until(EC.presence_of_element_located((By.CLASS_NAME, "vuln-card")))
        shot("03_laboratorio.png", "Portal del laboratorio con los seis vectores de prueba")

        # --- OWASP-01: XSS reflejado ---------------------------------------
        driver.get(f"{base_url}/lab/buscar?q={quote(XSS_PAYLOAD, safe='')}")
        wait_text("XSS EJECUTADO", "#banner-xss")
        shot("04_xss_reflejado.png", "XSS reflejado: el payload se ejecuta y modifica el DOM")
        data["verificaciones"]["OWASP-01"] = {
            "payload": XSS_PAYLOAD,
            "vulnerable": http_check("GET", "/lab/buscar", base_url=base_url,
                                     params={"q": XSS_PAYLOAD}, allow_redirects=False),
            "corregido": http_check("GET", "/lab/buscar_seguro", base_url=base_url,
                                    params={"q": XSS_PAYLOAD}, allow_redirects=False),
            "evidencia": "El contenido del parámetro q aparece sin escapar y se ejecuta el manejador onerror.",
        }

        driver.get(f"{base_url}/lab/buscar_seguro?q={quote(XSS_PAYLOAD, safe='')}")
        wait_text("payload tratado como texto", ".lab-banner.secure")
        shot("05_xss_corregido.png", "Versión corregida: escape de salida + CSP bloquean el payload")

        # --- OWASP-02: Inyección SQL ---------------------------------------
        driver.get(f"{base_url}/lab/login_sqli")
        driver.find_element(By.NAME, "username").send_keys(SQLI_PAYLOAD)
        driver.find_element(By.NAME, "password").send_keys("cualquiera")
        driver.find_element(By.CSS_SELECTOR, "button[type=submit]").click()
        wait_text("ACCESO CONCEDIDO", ".lab-banner")
        shot("06_sqli_bypass.png", "Inyección SQL: bypass de autenticación y volcado de usuarios")
        data["verificaciones"]["OWASP-02"] = {
            "payload": SQLI_PAYLOAD,
            "vulnerable": http_check("POST", "/lab/login_sqli", base_url=base_url,
                                     data={"username": SQLI_PAYLOAD, "password": "cualquiera"}),
            "corregido": http_check_csrf("POST", "/lab/login_seguro", base_url,
                                         data={"username": SQLI_PAYLOAD, "password": "cualquiera"}),
            "evidencia": "La consulta concatenada devuelve todos los usuarios; la versión ORM no.",
        }

        driver.get(f"{base_url}/lab/login_seguro")
        driver.find_element(By.NAME, "username").send_keys(SQLI_PAYLOAD)
        driver.find_element(By.NAME, "password").send_keys("cualquiera")
        driver.find_element(By.CSS_SELECTOR, "button[type=submit]").click()
        wait_text("Usuario o contraseña incorrectos", ".lab-banner")
        shot("07_sqli_corregido.png", "Versión corregida: consulta parametrizada, sin bypass")

        # --- OWASP-03: IDOR -------------------------------------------------
        driver.get(f"{base_url}/lab/perfil?id=2")
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "pre")))
        shot("08_idor.png", "IDOR: perfil ajeno consultado sin autenticación")
        data["verificaciones"]["OWASP-03"] = {
            "payload": "/lab/perfil?id=2",
            "vulnerable": http_check("GET", "/lab/perfil?id=2", base_url=base_url),
            "corregido": http_check("GET", "/lab/perfil_seguro?id=2", base_url=base_url),
            "evidencia": "El endpoint devuelve correo y rol de otro usuario sin verificar la sesión.",
        }

        # --- OWASP-04: CSRF por GET ----------------------------------------
        driver.get(f"{base_url}/lab/cambiar_rol?username=invitado&rol=admin")
        wait_text("Estado modificado", ".lab-banner")
        shot("09_csrf_get.png", "CSRF: una petición GET cambia el rol sin token ni autenticación")
        data["verificaciones"]["OWASP-04"] = {
            "payload": "/lab/cambiar_rol?username=invitado&rol=admin",
            "vulnerable": http_check("GET", "/lab/cambiar_rol?username=invitado&rol=admin",
                                     base_url=base_url),
            "corregido": http_check_csrf("POST", "/lab/cambiar_rol_seguro", base_url,
                                         data={"username": "invitado", "rol": "admin"}),
            "evidencia": "El estado cambia con un simple GET; la versión corregida exige POST, JWT de admin y CSRF.",
        }

        # --- OWASP-05: Configuración insegura ------------------------------
        driver.get(f"{base_url}/lab/sin_headers")
        wait_text("Configuración insegura confirmada", ".lab-banner")
        shot("10_headers_inseguros.png", "Respuesta sin cabeceras de seguridad")
        data["verificaciones"]["OWASP-05"] = {
            "payload": "/lab/sin_headers",
            "vulnerable": http_check("GET", "/lab/sin_headers", base_url=base_url),
            "corregido": http_check("GET", "/login", base_url=base_url),
            "evidencia": "Comparativa de cabeceras: la ruta vulnerable omite CSP, nosniff y X-Frame-Options.",
        }

        # --- OWASP-06: Errores detallados ----------------------------------
        driver.get(f"{base_url}/lab/error?detalle=select")
        wait_text("JWT_SECRET", ".lab-code")
        shot("11_error_verbose.png", "Fuga de información: traza con secretos y rutas internas")
        data["verificaciones"]["OWASP-06"] = {
            "payload": "/lab/error?detalle=select",
            "vulnerable": http_check("GET", "/lab/error?detalle=select", base_url=base_url),
            "corregido": http_check("GET", "/app/auditoria", base_url=base_url),
            "evidencia": "La respuesta expone JWT_SECRET, rutas del servidor y credenciales de base de datos.",
        }

        # --- Control positivo: RBAC ----------------------------------------
        driver.get(f"{base_url}/logout")
        driver.get(f"{base_url}/login")
        wait.until(EC.presence_of_element_located((By.ID, "login-form")))
        driver.find_element(By.NAME, "username").send_keys("estudiante")
        driver.find_element(By.NAME, "password").send_keys("Alumno123*")
        driver.find_element(By.CSS_SELECTOR, "#login-form button[type=submit]").click()
        wait.until(EC.url_contains("/app"))
        driver.get(f"{base_url}/app/usuarios")
        wait.until(EC.presence_of_element_located((By.CLASS_NAME, "error-code")))
        shot("12_rbac_denegado.png", "Control funcionando: estudiante recibe 403 en administración")
        data["verificaciones"]["CONTROL-RBAC"] = {
            "payload": "/app/usuarios con rol estudiante",
            "corregido": {"codigo": 403, "detalle": "Acceso denegado por RBAC"},
        }

        data["fecha"] = datetime.now(timezone.utc).isoformat()
        save_evidence(data)
        print(f"\nEvidencias guardadas en {SHOTS}")
        return data
    finally:
        driver.quit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:5000")
    parser.add_argument("--only-report", action="store_true")
    args = parser.parse_args()
    run(args.url, args.only_report)
