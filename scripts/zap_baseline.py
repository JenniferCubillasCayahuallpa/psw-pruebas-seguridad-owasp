"""Escaneo básico con OWASP ZAP (opcional).

Requiere ZAP ejecutándose con la API habilitada, por ejemplo:
  zap.bat -host 127.0.0.1 -port 8090 -config api.key=miclave -daemon

Uso:
  python scripts/zap_baseline.py --url http://127.0.0.1:5000 --api-key miclave

Guarda reports/zap_alerts.json. Si ZAP no está instalado, el informe igualmente
es reproducible con scripts/ejecutar_pruebas.py (evidencias Selenium + HTTP).
"""

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent

# Semillas del laboratorio: el spider anónimo sólo descubre /login, así que se
# escanean también las rutas vulnerables de la práctica.
LAB_PATHS = (
    "/lab/buscar?q=prueba",
    "/lab/login_sqli",
    "/lab/perfil?id=2",
    "/lab/cambiar_rol",
    "/lab/sin_headers",
    "/lab/error",
)

RISK_LEVELS = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def risk_value(alert: dict) -> int:
    """ZAP 2.17 entrega 'risk' como texto; versiones antiguas usaban 'riskId'."""
    text = str(alert.get("risk", "")).lower()
    if text in RISK_LEVELS:
        return RISK_LEVELS[text]
    return int(alert.get("riskId", 0) or 0)


class ZAPClient:
    def __init__(self, base_url: str, api_key: str):
        self.base = base_url.rstrip("/")
        self.key = api_key

    def call(self, component: str, endpoint: str, **params):
        url = f"{self.base}/JSON/{component}/{endpoint}/"
        params.setdefault("apikey", self.key)
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()

    def wait(self, component: str, scan_id: str, timeout: int = 300) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self.call(component, "view/status", scanId=scan_id)
            value = int(status.get("status", 0))
            if value >= 100:
                return
            time.sleep(2)
        raise TimeoutError(f"El escaneo {component} tardó más de {timeout}s")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:5000")
    parser.add_argument("--zap-url", default="http://127.0.0.1:8090")
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()

    zap = ZAPClient(args.zap_url, args.api_key)
    print("ZAP version:", zap.call("core", "view/version").get("version"))

    targets = [args.url.rstrip("/") + path for path in LAB_PATHS]
    if args.url.rstrip("/") not in targets:
        targets.insert(0, args.url.rstrip("/"))

    for target in targets:
        spider_id = zap.call("spider", "action/scan", url=target, maxChildren=20)["scan"]
        zap.wait("spider", spider_id)
        scan_id = zap.call("ascan", "action/scan", url=target, recurse=False)["scan"]
        zap.wait("ascan", scan_id)
        print("Escaneado:", target)

    alerts = zap.call("core", "view/alerts", baseurl=args.url).get("alerts", [])
    relevant = [
        {"name": a.get("name"), "risk": a.get("risk"), "url": a.get("url"),
         "param": a.get("param"), "description": a.get("description"),
         "solution": a.get("solution"), "cweid": a.get("cweid"), "wascid": a.get("wascid")}
        for a in alerts if risk_value(a) >= 1
    ]
    output = {
        "fecha": datetime.now(timezone.utc).isoformat(),
        "objetivo": args.url,
        "total_alertas": len(alerts),
        "alertas_relevantes": relevant,
    }
    path = ROOT / "reports" / "zap_alerts.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Alertas relevantes: {len(relevant)} -> {path}")


if __name__ == "__main__":
    main()
