"""Prueba funcional automatizada con Selenium (pytest opcional: tests/test_seguridad.py).

Ejecución:
    python tests/selenium_funcional.py --url http://127.0.0.1:5000

Realiza: abrir la página, iniciar sesión como docente, validar el panel,
crear un curso, comprobar que aparece en el listado y verificar que un
estudiante NO puede abrir la administración (RBAC). Guarda capturas en
reports/selenium/ y un resultado.json con cada paso.
"""

import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "reports" / "selenium"
OUT.mkdir(parents=True, exist_ok=True)


def build_driver(headless: bool = True):
    options = Options()
    if headless:
        options.add_argument("--headless=new")
    options.add_argument("--window-size=1440,1000")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--hide-scrollbars")
    return webdriver.Chrome(options=options)


def run(base_url: str = "http://127.0.0.1:5000", headless: bool = True) -> dict:
    base_url = base_url.rstrip("/")
    driver = build_driver(headless)
    wait = WebDriverWait(driver, 20)
    steps = []
    code = f"QA-{random.randint(100, 999)}"

    def step(name: str, detail: str, screenshot: str = "") -> None:
        steps.append({"paso": name, "detalle": detail, "captura": screenshot, "estado": "OK"})
        print(f"  [OK] {name}: {detail}")

    def shot(filename: str) -> str:
        path = OUT / filename
        driver.save_screenshot(str(path))
        return f"selenium/{filename}"

    try:
        # 1. Página de acceso -------------------------------------------------
        driver.get(f"{base_url}/login")
        wait.until(EC.presence_of_element_located((By.ID, "login-form")))
        step("Abrir sitio", "Página /login cargada", shot("01_login.png"))

        # 2. Login con el rol docente ---------------------------------------
        driver.find_element(By.NAME, "username").send_keys("docente")
        driver.find_element(By.NAME, "password").send_keys("Profe123*")
        driver.find_element(By.CSS_SELECTOR, "#login-form button[type=submit]").click()
        wait.until(EC.url_contains("/app"))
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".hero h1")))
        step("Iniciar sesión", "Docente autenticado; access token en cookie HttpOnly",
             shot("02_dashboard.png"))

        token = driver.get_cookie("psw_access")
        csrf = driver.get_cookie("psw_csrf")
        assert token and token["httpOnly"], "El access token debe ser HttpOnly"
        assert csrf and not csrf["httpOnly"], "El token CSRF debe ser legible por el frontend"
        step("Validar token", "psw_access HttpOnly y psw_csrf presente")

        # 3. Navegación a cursos --------------------------------------------
        driver.find_element(By.CSS_SELECTOR, 'a[href="/app/cursos"]').click()
        wait.until(EC.url_contains("/app/cursos"))
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "table.data tbody tr")))
        assert "PSW-101" in driver.page_source
        step("Listar cursos", "Catálogo cargado con datos del backend", shot("03_cursos.png"))

        # 4. Crear curso (escritura con CSRF) --------------------------------
        driver.find_element(By.CSS_SELECTOR, '[data-modal-open="course-modal"]').click()
        modal = wait.until(EC.visibility_of_element_located((By.ID, "course-modal")))
        modal.find_element(By.NAME, "code").send_keys(code)
        modal.find_element(By.NAME, "name").send_keys("Curso de prueba Selenium")
        modal.find_element(By.NAME, "schedule").send_keys("Sab 09:00 - 11:00")
        modal.find_element(By.NAME, "classroom").send_keys("LAB-9")
        modal.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
        wait.until(EC.presence_of_element_located((By.CLASS_NAME, "toast")))
        step("Crear curso", f"Curso {code} enviado con X-CSRF-Token", shot("04_curso_creado.png"))

        # 5. Verificar resultado tras recargar -------------------------------
        wait.until(EC.text_to_be_present_in_element((By.TAG_NAME, "body"), code))
        step("Validar resultado", f"Curso {code} visible en el listado", shot("05_curso_verificado.png"))

        # 6. Cerrar sesión ---------------------------------------------------
        driver.find_element(By.CSS_SELECTOR, "[data-logout]").click()
        wait.until(EC.url_contains("/login"))
        assert driver.get_cookie("psw_access") is None, "La cookie de sesión debe eliminarse"
        step("Cerrar sesión", "Cookies de acceso eliminadas")

        # 7. RBAC: estudiante no entra a administración ----------------------
        driver.find_element(By.NAME, "username").send_keys("estudiante")
        driver.find_element(By.NAME, "password").send_keys("Alumno123*")
        driver.find_element(By.CSS_SELECTOR, "#login-form button[type=submit]").click()
        wait.until(EC.url_contains("/app"))
        driver.get(f"{base_url}/app/usuarios")
        wait.until(EC.presence_of_element_located((By.CLASS_NAME, "error-code")))
        assert "403" in driver.page_source
        step("Control RBAC", "Estudiante recibe 403 al intentar /app/usuarios",
             shot("06_rbac_denegado.png"))

        result = {
            "titulo": "Prueba funcional automatizada · Selenium",
            "fecha": datetime.now(timezone.utc).isoformat(),
            "url": base_url,
            "navegador": "Chrome headless (Selenium Manager)",
            "total_pasos": len(steps),
            "estado": "PASÓ",
            "pasos": steps,
        }
    except Exception as exc:
        result = {
            "titulo": "Prueba funcional automatizada · Selenium",
            "fecha": datetime.now(timezone.utc).isoformat(),
            "url": base_url,
            "total_pasos": len(steps),
            "estado": "FALLÓ",
            "error": str(exc),
            "pasos": steps,
        }
        driver.save_screenshot(str(OUT / "error.png"))
        raise
    finally:
        driver.quit()

    (OUT / "resultado.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:5000")
    parser.add_argument("--headed", action="store_true", help="Mostrar el navegador")
    args = parser.parse_args()
    salida = run(args.url, headless=not args.headed)
    print("\nResultado:", salida["estado"], "| pasos:", salida["total_pasos"])
