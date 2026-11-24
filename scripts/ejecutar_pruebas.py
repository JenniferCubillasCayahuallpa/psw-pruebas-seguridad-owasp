"""Orquestador: levanta la app en modo laboratorio, ejecuta Selenium,
captura evidencias y genera el informe con capturas reales.

    python scripts/ejecutar_pruebas.py

Requiere Chrome instalado (Selenium Manager descarga el driver si hace falta).
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
LOGS = ROOT / "reports" / "server.log"


def wait_health(url: str, timeout: int = 40) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = requests.get(url + "/api/lab/estado", timeout=2)
            if response.status_code == 200 and response.json().get("lab_mode"):
                return True
        except requests.RequestException:
            pass
        time.sleep(0.5)
    return False


def run_script(script: str, *args: str) -> None:
    command = [sys.executable, str(ROOT / "scripts" / script), *args]
    if script == "selenium_funcional.py":
        command = [sys.executable, str(ROOT / "tests" / script), *args]
    print(f"\n>>> {' '.join(command)}")
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--skip-functional", action="store_true")
    args = parser.parse_args()

    url = f"http://127.0.0.1:{args.port}"
    LOGS.parent.mkdir(parents=True, exist_ok=True)
    process = None
    log = None

    # Si ya hay un servidor, comprobamos que sea el laboratorio antes de lanzar otro.
    try:
        existing = requests.get(url + "/api/lab/estado", timeout=2)
        if existing.status_code == 200 and existing.json().get("lab_mode"):
            print(f"Servidor en modo laboratorio ya activo en {url}; se reutiliza.")
        else:
            print(
                f"Ya hay un servidor en {url} que NO es el laboratorio (HTTP {existing.status_code}).\n"
                "Ciérralo con Ctrl+C y vuelve a ejecutar este script, o usa otro --port."
            )
            raise SystemExit(1)
    except requests.RequestException:
        log = LOGS.open("w", encoding="utf-8")
        process = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py"), "--lab", "--port", str(args.port)],
            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
        )

    try:
        if process is not None:
            print(f"Esperando servidor en {url} ...")
            if not wait_health(url):
                print("El servidor no respondió. Revisa reports/server.log")
                raise SystemExit(1)
        print("Servidor listo (LAB_MODE=1)")

        if not args.skip_functional:
            run_script("selenium_funcional.py", "--url", url)

        run_script("capturar_evidencias.py", "--url", url)
        run_script("generar_reporte.py")
        run_script("capturar_evidencias.py", "--url", url, "--only-report")

        print("\nProceso terminado correctamente.")
        print("  reports/selenium/resultado.json")
        print("  reports/evidencias.json")
        print("  reports/informe_seguridad.md / .html")
        print("  reports/capturas/*.png")
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                if sys.platform == "win32":
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], check=False)
                else:
                    process.kill()
        if log is not None:
            log.close()


if __name__ == "__main__":
    main()
