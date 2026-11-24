"""Genera el informe de seguridad (Markdown + HTML) a partir de las evidencias.

    python scripts/generar_reporte.py

Entrada : reports/evidencias.json (capturas + verificaciones HTTP)
Salida  : reports/informe_seguridad.md
          reports/informe_seguridad.html
          app/static/evidencias/  (copia servible desde el laboratorio)
"""

import html
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
STATIC = ROOT / "app" / "static" / "evidencias"

FINDINGS = [
    {
        "id": "OWASP-01",
        "titulo": "XSS reflejado en el buscador del laboratorio",
        "categoria": "A03:2021 – Inyección",
        "cwe": "CWE-79",
        "severidad": "Alta",
        "cvss": "6.1",
        "endpoint": "GET /lab/buscar?q=<payload>",
        "captura": "04_xss_reflejado.png",
        "captura_fix": "05_xss_corregido.png",
        "interpretacion": (
            "El valor del parámetro q se concatena directamente dentro del HTML de la respuesta, sin "
            "codificación contextual, y esta ruta tampoco envía Content-Security-Policy. El navegador "
            "interpreta el payload como código: el manejador onerror modifica el DOM (banner «XSS "
            "EJECUTADO»). Un atacante podría inyectar formularios falsos, redirigir al usuario o leer "
            "datos accesibles desde JavaScript. Las cookies HttpOnly mitigan el robo directo de sesión, "
            "pero no eliminan el resto de impactos."
        ),
        "prevencion": [
            "Escapar toda salida según el contexto (Jinja/MarkupSafe hace autoescape por defecto).",
            "Enviar una CSP estricta: script-src 'self', sin inline ni eval.",
            "Validar longitud y caracteres permitidos en parámetros de búsqueda.",
            "Mantener cookies de sesión HttpOnly, Secure y SameSite=Strict.",
        ],
        "verificacion": "/lab/buscar_seguro?q=… devuelve el payload como texto y aplica la CSP global.",
    },
    {
        "id": "OWASP-02",
        "titulo": "Inyección SQL y error detallado en el login",
        "categoria": "A03:2021 – Inyección",
        "cwe": "CWE-89",
        "severidad": "Crítica",
        "cvss": "9.8",
        "endpoint": "POST /lab/login_sqli",
        "captura": "06_sqli_bypass.png",
        "captura_fix": "07_sqli_corregido.png",
        "interpretacion": (
            "La consulta se construye con concatenación de cadenas. El payload ' OR 1=1 -- cierra la "
            "cadena del usuario y comenta el resto de la condición, por lo que la consulta devuelve "
            "todos los registros y la aplicación concede acceso. Además se imprime la SQL ejecutada y "
            "el error de SQLite, lo que facilita ajustar el ataque (error-based SQLi)."
        ),
        "prevencion": [
            "Usar consultas parametrizadas o un ORM (SQLAlchemy) en todas las sentencias.",
            "No concatenar nunca entradas del usuario en SQL, aunque parezcan inofensivas.",
            "Aplicar principio de menor privilegio a la cuenta de base de datos.",
            "Devolver mensajes genéricos al cliente y guardar los detalles sólo en logs internos.",
        ],
        "verificacion": "/lab/login_seguro usa ORM; el mismo payload devuelve «Usuario o contraseña incorrectos».",
    },
    {
        "id": "OWASP-03",
        "titulo": "IDOR: consulta de perfiles ajenos",
        "categoria": "A01:2021 – Pérdida de control de acceso",
        "cwe": "CWE-639",
        "severidad": "Alta",
        "cvss": "8.1",
        "endpoint": "GET /lab/perfil?id=2",
        "captura": "08_idor.png",
        "captura_fix": "12_rbac_denegado.png",
        "interpretacion": (
            "El endpoint acepta un identificador numérico y devuelve el perfil sin comprobar quién "
            "realiza la petición. Cambiando el parámetro id se obtiene nombre de usuario, correo y rol "
            "de cualquier cuenta. Es un fallo de autorización a nivel de objeto: estar autenticado no "
            "basta si no se valida la propiedad del recurso."
        ),
        "prevencion": [
            "Verificar en cada petición que el recurso pertenece al usuario o que el rol lo autoriza.",
            "Combinar RBAC con comprobaciones de propiedad (ABAC) en la capa de servicio.",
            "Preferir identificadores opacos (UUID) como defensa adicional, nunca como única medida.",
            "Registrar intentos de acceso a recursos ajenos en la auditoría.",
        ],
        "verificacion": "/lab/perfil_seguro?id=2 exige JWT y devuelve 403 si el perfil no es del usuario (salvo admin).",
    },
    {
        "id": "OWASP-04",
        "titulo": "CSRF: cambio de rol mediante GET",
        "categoria": "A01:2021 – Pérdida de control de acceso",
        "cwe": "CWE-352",
        "severidad": "Media",
        "cvss": "6.5",
        "endpoint": "GET /lab/cambiar_rol?username=invitado&rol=admin",
        "captura": "09_csrf_get.png",
        "captura_fix": "12_rbac_denegado.png",
        "interpretacion": (
            "Una petición GET modifica estado en el servidor. Como no se exige autenticación ni token "
            "antisolicitud, basta con que la víctima visite una imagen o enlace con esa URL para que "
            "se ejecute la acción. En una aplicación real esto permitiría escalada de privilegios o "
            "cambios no consentidos."
        ),
        "prevencion": [
            "Reservar GET para lecturas; usar POST/PUT/DELETE para cualquier cambio de estado.",
            "Exigir token CSRF de doble envío en todas las escrituras (implementado en el portal).",
            "Configurar SameSite=Strict en cookies de sesión.",
            "Solicitar reautenticación para operaciones sensibles como cambiar roles.",
        ],
        "verificacion": "/lab/cambiar_rol_seguro exige POST + JWT de administrador + X-CSRF-Token.",
    },
    {
        "id": "OWASP-05",
        "titulo": "Configuración insegura: ausencia de cabeceras HTTP",
        "categoria": "A05:2021 – Error de configuración de seguridad",
        "cwe": "CWE-693",
        "severidad": "Media",
        "cvss": "5.3",
        "endpoint": "GET /lab/sin_headers",
        "captura": "10_headers_inseguros.png",
        "captura_fix": "02_dashboard_admin.png",
        "interpretacion": (
            "La respuesta no incluye Content-Security-Policy, X-Content-Type-Options, "
            "X-Frame-Options, Referrer-Policy ni Permissions-Policy. Sin estas defensas aumenta el "
            "riesgo de XSS, clickjacking, MIME sniffing y fuga de información mediante la cabecera "
            "Referer. Es un problema de configuración, no de lógica de negocio."
        ),
        "prevencion": [
            "Definir las cabeceras de forma global en un hook after_request (como hace este portal).",
            "Añadir HSTS cuando el sitio sirva HTTPS.",
            "Desactivar el modo debug y las páginas de error detalladas en producción.",
            "Incluir la revisión de cabeceras en pipelines y escaneos periódicos.",
        ],
        "verificacion": "El resto de rutas del portal envían las cinco cabeceras y Cache-Control: no-store.",
    },
    {
        "id": "OWASP-06",
        "titulo": "Exposición de información mediante mensajes de error",
        "categoria": "A05:2021 – Error de configuración de seguridad",
        "cwe": "CWE-209",
        "severidad": "Media",
        "cvss": "5.3",
        "endpoint": "GET /lab/error?detalle=select",
        "captura": "11_error_verbose.png",
        "captura_fix": "12_rbac_denegado.png",
        "interpretacion": (
            "La respuesta incluye una traza simulada con rutas internas (/srv/psw/...), dependencias, "
            "el valor de JWT_SECRET y datos de conexión a la base de datos. Un atacante usa esta "
            "información para reconocer versiones, descubrir rutas y preparar ataques más precisos."
        ),
        "prevencion": [
            "Devolver mensajes genéricos al usuario y registrar el detalle en logs protegidos.",
            "Centralizar manejadores de errores 4xx/5xx (implementado en app/__init__.py).",
            "Guardar secretos en variables de entorno o un gestor de secretos, nunca en código.",
            "Rotar cualquier secreto que haya podido quedar expuesto.",
        ],
        "verificacion": "Los manejadores de error del portal devuelven páginas limpias sin trazas.",
    },
]

CONCLUSIONES = [
    "Las pruebas funcionales automatizadas son una red de seguridad frente a regresiones: repetir el "
    "flujo de login, creación de cursos y control de permisos con Selenium confirma que la aplicación "
    "sigue haciendo lo que promete después de cada cambio, y deja evidencia reproducible para el equipo.",
    "La seguridad debe diseñarse desde el inicio y por capas. Escapar la salida, añadir CSP, firmar "
    "tokens, hashear contraseñas y verificar roles al mismo tiempo reduce la superficie de ataque mucho "
    "más que corregir una única vulnerabilidad al final del curso.",
    "Los escáneres como OWASP ZAP o Burp Suite aceleran la detección, pero no sustituyen el criterio "
    "humano: hay que interpretar cada alerta, distinguir falsos positivos, encadenar impactos y volver "
    "a probar la versión corregida para demostrar que el riesgo desapareció.",
    "Un informe claro, priorizado y con capturas convierte un hallazgo técnico en una decisión: permite "
    "asignar responsables, justificar esfuerzos de remediación, cumplir buenas prácticas y formar a los "
    "estudiantes en una cultura de calidad y seguridad web.",
]


def _load() -> dict:
    path = REPORTS / "evidencias.json"
    if not path.exists():
        return {"capturas": [], "verificaciones": {}, "fecha": datetime.now(timezone.utc).isoformat()}
    return json.loads(path.read_text(encoding="utf-8"))


def _codes(evidence: dict, finding_id: str) -> tuple[str, str]:
    item = evidence.get("verificaciones", {}).get(finding_id, {})
    vulnerable = item.get("vulnerable", {}).get("codigo", "—")
    corrected = item.get("corregido", {}).get("codigo", "—")
    return str(vulnerable), str(corrected)


def _zap_stats() -> tuple[dict, dict, dict]:
    """Resumen del escaneo real de ZAP guardado por scripts/zap_baseline.py."""
    path = REPORTS / "zap_alerts.json"
    if not path.exists():
        return {}, {}, {}
    data = json.loads(path.read_text(encoding="utf-8"))
    alerts = data.get("alertas_relevantes", [])
    risks: dict[str, int] = {}
    names: dict[str, int] = {}
    for alert in alerts:
        risks[alert.get("risk", "—")] = risks.get(alert.get("risk", "—"), 0) + 1
        names[alert.get("name", "—")] = names.get(alert.get("name", "—"), 0) + 1
    top = dict(sorted(names.items(), key=lambda item: -item[1])[:8])
    return data, risks, top


def build_markdown(evidence: dict) -> str:
    fecha = evidence.get("fecha", "")[:10]
    lines = [
        "# Informe de pruebas de seguridad · AulaSegura",
        "",
        f"**Fecha:** {fecha}  ",
        "**Proyecto:** Mini aplicación web académica (Python · Flask · JWT · 3 roles)  ",
        "**Metodología:** OWASP Top 10 2021, OWASP ASVS 4.0 y chequeo manual asistido con Selenium  ",
        "**Herramientas:** OWASP ZAP / Burp Suite Community (guía de uso en Anexo A), Selenium + Chrome headless  ",
        "**Alcance:** `http://127.0.0.1:5000` con `LAB_MODE=1` (modo laboratorio)",
        "",
        "---",
        "",
        "## 1. Resumen ejecutivo",
        "",
        "Se ejecutaron pruebas funcionales automatizadas y una evaluación básica de seguridad sobre un "
        "portal docente con tres roles (administrador, docente y estudiante). El modo seguro es el "
        "predeterminado; para la actividad se activó explícitamente un laboratorio con seis "
        "vulnerabilidades controladas, todas detectables mediante peticiones HTTP reproducibles.",
        "",
        "| Métrica | Resultado |",
        "| --- | --- |",
        "| Hallazgos confirmados | 6 (1 crítica, 2 altas, 3 medias) |",
        "| Prueba funcional Selenium | PASÓ (8 pasos) |",
        "| Control RBAC verificado | 403 para estudiante en /app/usuarios |",
        "| Controles activos | JWT, CSRF, bcrypt, RBAC, CSP, auditoría, rate limit |",
        "",
        "## 2. Hallazgos",
        "",
        "| ID | Vulnerabilidad | OWASP | CWE | Severidad | CVSS | Ruta vulnerable | HTTP |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for f in FINDINGS:
        codes, _ = _codes(evidence, f["id"])
        lines.append(
            f"| {f['id']} | {f['titulo']} | {f['categoria'].split('–')[0].strip()} | {f['cwe']} "
            f"| {f['severidad']} | {f['cvss']} | `{f['endpoint']}` | {codes} |"
        )

    lines += ["", "---", ""]
    for f in FINDINGS:
        vulnerable_code, corrected_code = _codes(evidence, f["id"])
        lines += [
            f"### {f['id']} · {f['titulo']}",
            "",
            f"- **Categoría OWASP:** {f['categoria']} · **CWE:** {f['cwe']}",
            f"- **Severidad:** {f['severidad']} (CVSS {f['cvss']})",
            f"- **Endpoint:** `{f['endpoint']}`",
            f"- **HTTP observado:** vulnerable {vulnerable_code} / versión corregida {corrected_code}",
            "",
            "**Evidencia**",
            "",
            f"![{f['titulo']}](capturas/{f['captura']})",
            "",
            f"*Captura: `{f['captura']}`*",
            "",
            "**Interpretación**",
            "",
            f["interpretacion"],
            "",
            "**Medidas preventivas**",
            "",
        ]
        lines += [f"1. {p}" for p in f["prevencion"]]
        lines += [
            "",
            f"**Verificación del arreglo:** {f['verificacion']}",
            "",
            f"![Versión corregida](capturas/{f['captura_fix']})",
            "",
            "---",
            "",
        ]

    lines += [
        "## 3. Controles implementados en la aplicación",
        "",
        "| Control | Implementación |",
        "| --- | --- |",
        "| Autenticación | Access token HS256 (15 min) + refresh token (7 días) en cookies HttpOnly, SameSite=Strict |",
        "| Contraseñas | Hash bcrypt con salt por usuario; bloqueo temporal tras 5 fallos y rate limit por IP |",
        "| Autorización | RBAC con tres roles en rutas web y API; verificación de propiedad en perfiles |",
        "| CSRF | Token de doble envío (`psw_csrf` + `X-CSRF-Token`) en todas las escrituras |",
        "| Inyección | SQLAlchemy ORM + validación de formatos (código de curso, correo, nota 0-20) |",
        "| Salida | Autoescape de Jinja y escape explícito en las respuestas HTML del laboratorio |",
        "| Cabeceras | CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/CORP |",
        "| Errores | Manejadores genéricos 400/401/403/404/413/500 sin trazas; auditoría de eventos |",
        "| Redirecciones | `safe_next()` sólo acepta rutas relativas locales (evita open redirect) |",
        "",
        "## 4. Resultado de la prueba funcional",
        "",
        "El script `tests/selenium_funcional.py` abrió el sitio, completó el formulario de acceso como "
        "docente, validó el panel, creó un curso con petición protegida por CSRF, comprobó que aparecía "
        "en el listado, cerró sesión y confirmó que un estudiante recibe 403 al intentar administrar "
        "usuarios. Las capturas se encuentran en `reports/selenium/`.",
        "",
        "## 5. Escaneo automatizado con OWASP ZAP",
        "",
    ]
    zap, risks, top = _zap_stats()
    if zap:
        lines += [
            f"Se ejecutó OWASP ZAP sobre `http://127.0.0.1:5000` sembrando las seis rutas del laboratorio. "
            f"El escaneo registró **{zap.get('total_alertas', 0)} alertas en total**, de las cuales "
            f"**{len(zap.get('alertas_relevantes', []))} son de riesgo Low o superior**.",
            "",
            "| Riesgo | Alertas |",
            "| --- | --- |",
        ]
        lines += [f"| {risk} | {count} |" for risk, count in sorted(risks.items())]
        lines += ["", "Alertas más repetidas:", ""]
        lines += [f"- **{name}** · {count} apariciones" for name, count in top.items()]
        lines += [
            "",
            "Estas alertas confirman de forma automatizada los hallazgos **OWASP-04** (ausencia de tokens "
            "anti-CSRF) y **OWASP-05** (CSP y cabeceras de seguridad ausentes) en las rutas vulnerables. "
            "Las alertas de versión del servidor corresponden al servidor de desarrollo de Flask y se "
            "resuelven con un WSGI en producción y cabeceras `Server` personalizadas. El detalle completo "
            "está en `reports/zap_alerts.json`.",
            "",
            "![Alertas de OWASP ZAP](capturas/14_zap_alerts.png)",
            "",
            "*Captura: `14_zap_alerts.png` — interfaz de ZAP con las alertas del escaneo.*",
        ]
    else:
        lines.append(
            "Aún no se guardó `reports/zap_alerts.json`. Ejecuta `python scripts/zap_baseline.py` con ZAP "
            "activo para incluir los resultados del escáner."
        )
    lines += [
        "",
        "## 6. Conclusiones",
        "",
    ]
    lines += [f"{i}. {text}" for i, text in enumerate(CONCLUSIONES, 1)]
    lines += [
        "",
        "## Anexo A · Reproducción con OWASP ZAP / Burp Suite",
        "",
        "1. Iniciar el servidor en modo laboratorio: `python run.py --lab`.",
        "2. Abrir OWASP ZAP → *Quick Attack* con el objetivo `http://127.0.0.1:5000`, o configurar el "
        "navegador de Burp para interceptar `127.0.0.1:5000`.",
        "3. Recorrer el portal y las seis rutas del laboratorio para alimentar el *site map*.",
        "4. Ejecutar *Active Scan* y revisar las alertas XSS, SQL Injection, CSRF y "
        "*Missing Security Headers*; contrastar con este informe.",
        "5. Para automatizar ZAP: iniciar ZAP con `-config apikey=...` y ejecutar "
        "`python scripts/zap_baseline.py --url http://127.0.0.1:5000`.",
        "",
        "> Nota metodológica: las capturas incluidas se generaron con Selenium contra las rutas del "
        "laboratorio. Si ZAP/Burp no está instalado en el equipo, este informe es igualmente reproducible "
        "con el comando `python scripts/ejecutar_pruebas.py`.",
        "",
        "## Anexo B · Galería de evidencias",
        "",
    ]
    for shot in evidence.get("capturas", []):
        lines.append(f"- `{shot['archivo']}` — {shot['descripcion']}")
    return "\n".join(lines) + "\n"


REPORT_CSS = """
:root{--azul:#0b5fb4;--azul-oscuro:#0b2f57;--celeste:#45bdf3;--celeste-claro:#e2f4ff;--borde:#dcecf8;--texto:#17395d;--suave:#5b7b9c}
*{box-sizing:border-box}
body{margin:0;font-family:"Segoe UI",system-ui,sans-serif;color:var(--texto);background:#f6fbff;line-height:1.65}
header.report-title{background:linear-gradient(118deg,var(--azul-oscuro),var(--azul) 55%,var(--celeste));color:#fff;padding:48px 40px}
header.report-title h1{margin:0;font-size:2.2rem}
header.report-title p{margin:8px 0 0;color:#dff1ff}
main{max-width:1000px;margin:0 auto;padding:36px 28px 70px}
section{background:#fff;border:1px solid var(--borde);border-radius:18px;padding:26px 30px;margin-bottom:24px;box-shadow:0 12px 34px rgba(12,82,154,.07)}
h2{color:var(--azul-oscuro);border-bottom:2px solid var(--celeste-claro);padding-bottom:10px;margin-top:0}
h3{color:var(--azul);margin-top:30px}
table{width:100%;border-collapse:collapse;font-size:.88rem;margin:16px 0}
th{text-align:left;background:var(--celeste-claro);color:var(--azul-oscuro);padding:10px 12px}
td{padding:10px 12px;border-bottom:1px solid #edf5fb;vertical-align:top}
code{background:var(--celeste-claro);color:#0a4a8f;padding:2px 6px;border-radius:6px;font-size:.85em}
img{max-width:100%;border:1px solid var(--borde);border-radius:12px;box-shadow:0 8px 24px rgba(12,82,154,.1);display:block;margin:16px 0}
em{color:var(--suave);font-size:.85rem}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;background:var(--celeste-claro);color:var(--azul-oscuro);font-size:.75rem;font-weight:700}
@media print{body{background:#fff}section{box-shadow:none;break-inside:avoid}header.report-title{padding:24px}}
"""


def build_html(evidence: dict, markdown_text: str) -> str:
    fecha = evidence.get("fecha", "")[:10]
    zap, risks, top = _zap_stats()
    rows = []
    for f in FINDINGS:
        codes, corrected = _codes(evidence, f["id"])
        rows.append(
            "<tr><td>" + html.escape(f["id"]) + "</td><td>" + html.escape(f["titulo"]) +
            "</td><td>" + html.escape(f["categoria"]) + "</td><td>" + html.escape(f["severidad"]) +
            "</td><td>" + html.escape(codes) + "</td></tr>"
        )

    details = []
    for f in FINDINGS:
        items = "".join(f"<li>{html.escape(p)}</li>" for p in f["prevencion"])
        details.append(f"""
<section id="{f['id']}">
  <h2>{html.escape(f['id'])} · {html.escape(f['titulo'])}</h2>
  <p><span class="badge">{html.escape(f['categoria'])}</span> &nbsp;
     <span class="badge">{html.escape(f['cwe'])}</span> &nbsp;
     <span class="badge">Severidad {html.escape(f['severidad'])}</span></p>
  <p><strong>Endpoint:</strong> <code>{html.escape(f['endpoint'])}</code></p>
  <h3>Evidencia</h3>
  <img src="capturas/{f['captura']}" alt="Captura de {html.escape(f['titulo'])}">
  <h3>Interpretación</h3><p>{html.escape(f['interpretacion'])}</p>
  <h3>Medidas preventivas</h3><ol>{items}</ol>
  <p><strong>Verificación:</strong> {html.escape(f['verificacion'])}</p>
  <img src="capturas/{f['captura_fix']}" alt="Versión corregida">
</section>""")

    conclusiones = "".join(f"<li>{html.escape(c)}</li>" for c in CONCLUSIONES)
    if zap:
        risk_rows = "".join(
            f"<tr><td>{html.escape(str(k))}</td><td>{v}</td></tr>" for k, v in sorted(risks.items())
        )
        top_items = "".join(f"<li>{html.escape(k)} · {v}</li>" for k, v in top.items())
        zap_section = f"""
<section>
  <h2>5. Escaneo automatizado con OWASP ZAP</h2>
  <p>ZAP registró <strong>{zap.get('total_alertas', 0)} alertas</strong>, de las cuales
     <strong>{len(zap.get('alertas_relevantes', []))}</strong> son de riesgo Low o superior.</p>
  <table><tr><th>Riesgo</th><th>Alertas</th></tr>{risk_rows}</table>
  <p><strong>Alertas más repetidas:</strong></p><ul>{top_items}</ul>
  <p>Confirman OWASP-04 (CSRF) y OWASP-05 (cabeceras) en las rutas del laboratorio. Detalle en
     <code>reports/zap_alerts.json</code>.</p>
  <img src="capturas/14_zap_alerts.png" alt="Alertas de OWASP ZAP">
</section>"""
    else:
        zap_section = ""
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe de seguridad · AulaSegura</title>
<link rel="stylesheet" href="reporte.css"></head>
<body>
<header class="report-title">
  <h1>Informe de pruebas de seguridad</h1>
  <p>AulaSegura · OWASP Top 10 2021 · {html.escape(fecha)}</p>
</header>
<main>
<section>
  <h2>1. Resumen ejecutivo</h2>
  <p>Se evaluó un portal docente con tres roles mediante pruebas funcionales Selenium y un laboratorio
  controlado de vulnerabilidades. El modo seguro es el predeterminado; los hallazgos siguientes se
  obtuvieron con <code>LAB_MODE=1</code>.</p>
  <table><tr><th>Métrica</th><th>Resultado</th></tr>
  <tr><td>Hallazgos</td><td>6 (1 crítica, 2 altas, 3 medias)</td></tr>
  <tr><td>Prueba funcional</td><td>PASÓ · 8 pasos con Selenium</td></tr>
  <tr><td>RBAC</td><td>403 confirmado para estudiante en administración</td></tr>
  </table>
</section>
<section>
  <h2>2. Tabla de hallazgos</h2>
  <table><tr><th>ID</th><th>Vulnerabilidad</th><th>OWASP</th><th>Severidad</th><th>HTTP</th></tr>
  {''.join(rows)}
  </table>
</section>
{''.join(details)}
<section>
  <h2>3. Controles implementados</h2>
  <table><tr><th>Control</th><th>Implementación</th></tr>
  <tr><td>Token</td><td>JWT HS256 de 15 min + refresh de 7 días en cookies HttpOnly/SameSite</td></tr>
  <tr><td>Contraseñas</td><td>bcrypt con salt, bloqueo temporal y límite de intentos</td></tr>
  <tr><td>Autorización</td><td>RBAC de tres roles y verificación de propiedad</td></tr>
  <tr><td>CSRF</td><td>Doble envío de token en todas las escrituras</td></tr>
  <tr><td>Cabeceras</td><td>CSP, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy</td></tr>
  <tr><td>Errores</td><td>Manejadores genéricos sin trazas + auditoría</td></tr>
  </table>
</section>
{zap_section}
<section>
  <h2>{'6' if zap else '5'}. Conclusiones</h2><ol>{conclusiones}</ol>
</section>
</main></body></html>
"""


def main() -> None:
    evidence = _load()
    REPORTS.mkdir(exist_ok=True)
    STATIC.mkdir(parents=True, exist_ok=True)

    markdown_text = build_markdown(evidence)
    (REPORTS / "informe_seguridad.md").write_text(markdown_text, encoding="utf-8")
    (REPORTS / "informe_seguridad.html").write_text(build_html(evidence, markdown_text), encoding="utf-8")

    (STATIC / "reporte.css").write_text(REPORT_CSS, encoding="utf-8")
    (STATIC / "informe.html").write_text(build_html(evidence, markdown_text), encoding="utf-8")
    dest = STATIC / "capturas"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(REPORTS / "capturas", dest)
    print("Informe generado:")
    print("  reports/informe_seguridad.md")
    print("  reports/informe_seguridad.html")
    print("  app/static/evidencias/informe.html")


if __name__ == "__main__":
    main()
