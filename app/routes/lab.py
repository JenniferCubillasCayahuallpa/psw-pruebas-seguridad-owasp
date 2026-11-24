"""Laboratorio OWASP: endpoints VULNERABLES A PROPÓSITO.

Sólo se registran cuando LAB_MODE=1. Sirven para que OWASP ZAP / Burp Suite
encuentren hallazgos reales en un entorno controlado y para tomar evidencias.
Cada vulnerabilidad tiene su versión segura junto a ella.
"""

import sqlite3
from markupsafe import escape

from flask import Blueprint, abort, current_app, g, jsonify, make_response, request

from ..extensions import db
from ..models import User
from ..security import audit, require_auth, require_csrf

bp = Blueprint("lab", __name__)

# Estado mutable de demostración para el ejemplo de CSRF.
_lab_roles = {"invitado": "estudiante"}


def _only_in_lab():
    if not current_app.config["LAB_MODE"]:
        abort(404)


def _no_headers():
    """Marca la respuesta para que after_request no añada cabeceras de seguridad."""
    g.skip_security_headers = True


def _shell(title: str, body: str, extra_css: str = "") -> str:
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · Laboratorio OWASP</title>
<link rel="stylesheet" href="/static/css/styles.css">
<style>{extra_css}</style>
</head><body class="lab-page">
<main class="lab-result">
  <a class="back-link" href="/app/laboratorio">← Volver al laboratorio</a>
  <span class="lab-chip">MODO LABORATORIO · vulnerable a propósito</span>
  {body}
</main></body></html>"""


@bp.get("/api/lab/estado")
def estado():
    return jsonify(lab_mode=current_app.config["LAB_MODE"],
                   modulos=["xss_reflejado", "sqli", "idor", "csrf_get",
                            "cabeceras_inseguras", "error_verbose"])


@bp.get("/lab/buscar")
def xss_reflejado():
    """A03:2021 Injection · XSS reflejado (sin escapar, sin CSP)."""
    _only_in_lab()
    _no_headers()
    q = request.args.get("q", "")
    body = f"""
  <h1>Búsqueda en el catálogo</h1>
  <p class="muted">El valor del parámetro <code>q</code> se inserta directamente en el HTML.</p>
  <form method="get" action="/lab/buscar" class="lab-form">
    <input name="q" value="{escape(q)}" placeholder="Escribe una búsqueda">
    <button class="btn primary" type="submit">Buscar</button>
  </form>
  <div class="lab-output">
    <strong>Resultados para:</strong> {q}
  </div>
  <div id="banner-xss" class="lab-banner">Estado: sin evidencia de ejecución</div>
"""
    return make_response(_shell("XSS reflejado", body))


@bp.get("/lab/buscar_seguro")
def xss_seguro():
    """Versión corregida: escapado de salida + CSP global."""
    _only_in_lab()
    q = request.args.get("q", "")
    body = f"""
  <h1>Búsqueda segura</h1>
  <p class="muted">El valor se escapa con <code>markupsafe.escape</code> y la CSP bloquea scripts inline.</p>
  <form method="get" action="/lab/buscar_seguro" class="lab-form">
    <input name="q" value="{escape(q)}" placeholder="Escribe una búsqueda">
    <button class="btn primary" type="submit">Buscar</button>
  </form>
  <div class="lab-output ok">
    <strong>Resultados para:</strong> {escape(q)}
  </div>
  <div class="lab-banner secure">Estado: payload tratado como texto, no como código</div>
"""
    return make_response(_shell("XSS corregido", body))


@bp.route("/lab/login_sqli", methods=["GET", "POST"])
def sqli():
    """A03:2021 Injection · concatenación directa de SQL + error detallado."""
    _only_in_lab()
    _no_headers()
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    query = (
        "SELECT id, username, full_name, role FROM lab_users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    conn = sqlite3.connect(":memory:")
    conn.execute("""CREATE TABLE lab_users (
        id INTEGER PRIMARY KEY, username TEXT, password TEXT, full_name TEXT, role TEXT)""")
    conn.executemany(
        "INSERT INTO lab_users VALUES (?,?,?,?,?)",
        [(1, "admin", "Admin123*", "Ana Salazar", "admin"),
         (2, "docente", "Profe123*", "Luis Ramírez", "docente"),
         (3, "invitado", "Invitado123*", "Usuario invitado", "estudiante")],
    )
    try:
        rows = conn.execute(query).fetchall()
        error = ""
    except sqlite3.Error as exc:
        rows = []
        error = f"sqlite3.OperationalError: {exc}"
    finally:
        conn.close()

    if rows:
        filas = "".join(
            f"<tr><td>{escape(r[0])}</td><td>{escape(r[1])}</td>"
            f"<td>{escape(r[2])}</td><td>{escape(r[3])}</td></tr>" for r in rows
        )
        resultado = (
            '<div class="lab-banner danger">ACCESO CONCEDIDO · inyección SQL detectada</div>'
            f'<table class="lab-table"><thead><tr><th>id</th><th>usuario</th>'
            f'<th>nombre</th><th>rol</th></tr></thead><tbody>{filas}</tbody></table>'
        )
        audit("lab_sqli_explotado", f"Payload username={username[:60]}", "warn")
    else:
        resultado = '<div class="lab-banner">Sin coincidencias. Revisa el error detallado.</div>'

    body = f"""
  <h1>Login del laboratorio (inseguro)</h1>
  <p class="muted">Prueba con usuario <code>' OR 1=1 --</code> y cualquier contraseña.</p>
  <form method="post" action="/lab/login_sqli" class="lab-form stacked">
    <label>Usuario <input name="username" value="{escape(username)}"></label>
    <label>Contraseña <input name="password" type="password" value="{escape(password)}"></label>
    <button class="btn primary" type="submit">Iniciar sesión</button>
  </form>
  {resultado}
  <div class="lab-code"><strong>Consola del servidor (información sensible expuesta):</strong>
  <pre>SQL ejecutada: {escape(query)}
{escape(error)}</pre></div>
"""
    return make_response(_shell("Inyección SQL", body))


@bp.route("/lab/login_seguro", methods=["GET", "POST"])
@require_csrf
def sqli_seguro():
    """Versión corregida: consulta parametrizada (SQLAlchemy ORM)."""
    _only_in_lab()
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user = User.query.filter_by(username=username).first()
    ok = bool(user and user.check_password(password))
    mensaje = ("Inicio de sesión correcto" if ok else "Usuario o contraseña incorrectos")
    cls = "secure" if ok else "danger"
    body = f"""
  <h1>Login parametrizado (seguro)</h1>
  <p class="muted">La consulta usa ORM y parámetros: el payload se compara como texto literal.</p>
  <form method="post" action="/lab/login_seguro" class="lab-form stacked">
    <input type="hidden" name="csrf_token" value="{escape(request.cookies.get('psw_csrf', ''))}">
    <label>Usuario <input name="username" value="{escape(username)}"></label>
    <label>Contraseña <input name="password" type="password"></label>
    <button class="btn primary" type="submit">Iniciar sesión</button>
  </form>
  <div class="lab-banner {cls}">{mensaje}</div>
"""
    return make_response(_shell("SQL corregido", body))


@bp.get("/lab/perfil")
def idor():
    """A01:2021 Broken Access Control · IDOR sin verificación de propiedad."""
    _only_in_lab()
    try:
        user_id = int(request.args.get("id", 1))
    except ValueError:
        user_id = 1
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify(error="Usuario no encontrado"), 404
    return jsonify(id=user.id, username=user.username, email=user.email,
                   full_name=user.full_name, role=user.role,
                   aviso="Datos devueltos sin comprobar quién realiza la petición")


@bp.get("/lab/perfil_seguro")
@require_auth()
def idor_seguro():
    """Versión corregida: el usuario sólo ve su propio perfil (o admin ve todos)."""
    _only_in_lab()
    try:
        user_id = int(request.args.get("id", g.current_user.id))
    except ValueError:
        user_id = g.current_user.id
    if user_id != g.current_user.id and g.current_user.role != "admin":
        return jsonify(error="No puedes consultar el perfil de otra persona"), 403
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify(error="Usuario no encontrado"), 404
    return jsonify(id=user.id, username=user.username, email=user.email,
                   full_name=user.full_name, role=user.role)


@bp.get("/lab/cambiar_rol")
def csrf_get():
    """A01:2021 Broken Access Control · cambio de estado mediante GET (CSRF)."""
    _only_in_lab()
    _no_headers()
    username = request.args.get("username", "invitado")
    nuevo_rol = request.args.get("rol", "estudiante")
    anterior = _lab_roles.get(username, "inexistente")
    _lab_roles[username] = nuevo_rol[:20]
    audit("lab_csrf_get", f"Rol de {username}: {anterior} -> {nuevo_rol}", "warn")
    body = f"""
  <h1>Cambio de rol (inseguro)</h1>
  <p class="muted">Una simple URL cambia el estado del servidor: cualquier sitio puede dispararla.</p>
  <div class="lab-banner danger">Estado modificado sin token CSRF ni autenticación</div>
  <div class="lab-output"><code>{escape(username)}</code>:
    <strong>{escape(anterior)}</strong> → <strong>{escape(_lab_roles[username])}</strong></div>
  <pre class="lab-code">GET /lab/cambiar_rol?username={escape(username)}&amp;rol={escape(nuevo_rol)}</pre>
"""
    return make_response(_shell("CSRF por GET", body))


@bp.post("/lab/cambiar_rol_seguro")
@require_auth(("admin",))
@require_csrf
def csrf_seguro():
    """Versión corregida: POST + JWT de administrador + token CSRF."""
    _only_in_lab()
    username = str(request.form.get("username") or "")
    nuevo_rol = str(request.form.get("rol") or "")
    if nuevo_rol not in {"admin", "docente", "estudiante"} or not username:
        return jsonify(error="Datos no válidos"), 400
    _lab_roles[username] = nuevo_rol
    audit("lab_csrf_seguro", f"Rol de {username} cambiado con CSRF + RBAC", "info")
    return jsonify(ok=True, username=username, role=nuevo_rol)


@bp.get("/lab/sin_headers")
def cabeceras_inseguras():
    """A05:2021 Security Misconfiguration · sin cabeceras de defensa en profundidad."""
    _only_in_lab()
    _no_headers()
    body = """
  <h1>Respuesta sin cabeceras de seguridad</h1>
  <p class="muted">Esta respuesta omite Content-Security-Policy, X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy y Permissions-Policy.</p>
  <div class="lab-banner danger">Configuración insegura confirmada</div>
  <p>Compara con cualquier otra página del portal: todas incluyen las cinco cabeceras.</p>
"""
    return make_response(_shell("Cabeceras inseguras", body))


@bp.get("/lab/error")
def error_verbose():
    """A05:2021 · trazas y datos internos filtrados al usuario."""
    _only_in_lab()
    _no_headers()
    detalle = escape(request.args.get("detalle", "consulta fallida"))
    body = f"""
  <h1>Error detallado expuesto</h1>
  <p class="muted">Los mensajes internos revelan rutas, dependencias y secretos.</p>
  <pre class="lab-code">Traceback (most recent call last):
  File "/srv/psw/app/routes/lab.py", line 88, in error_verbose
    ejecutar_consulta(detalle={detalle})
  File "/srv/psw/app/db.py", line 41, in ejecutar_consulta
    cursor.execute(sql)
sqlite3.OperationalError: near "{detalle}": syntax error
  [config] JWT_SECRET="dev-only-no-usar-en-produccion-cambiar"
  [config] DEBUG=True  DB_HOST="10.0.4.12"  DB_USER="psw_admin"
  [stack] /srv/psw/app/security.py:create_token -> /srv/psw/app/routes/auth.py:api_login</pre>
  <div class="lab-banner danger">Fuga de información: rutas, credenciales y configuración</div>
"""
    return make_response(_shell("Error verbose", body), 500)
