"""Controles de seguridad: JWT, CSRF, RBAC, auditoría y límite de intentos.

Diseño:
* Access token (15 min) y refresh token (7 días) firmados HS256.
* Access token via cookie HttpOnly + cabecera Bearer opcional (para clientes API).
* Refresh token en cookie HttpOnly con path restringido a /api/auth/refresh.
* Token CSRF de doble envío (cookie legible + cabecera X-CSRF-Token).
* Autorización basada en roles (RBAC) decorada en cada endpoint.
"""

import hmac
import secrets
import threading
import time
from datetime import timedelta
from functools import wraps

from flask import current_app, g, jsonify, make_response, redirect, request
from jose import JWTError, jwt

from .extensions import db
from .models import AuditLog, User, utcnow

COOKIE_ACCESS = "psw_access"
COOKIE_REFRESH = "psw_refresh"
COOKIE_CSRF = "psw_csrf"

_attempts: dict[str, dict] = {}
_attempts_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# Tokens JWT
# --------------------------------------------------------------------------- #
def _secret() -> str:
    return current_app.config["JWT_SECRET"]


def create_token(user: User, kind: str) -> str:
    minutes = (
        current_app.config["ACCESS_TTL_MINUTES"]
        if kind == "access"
        else current_app.config["REFRESH_TTL_DAYS"] * 24 * 60
    )
    now = utcnow()
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "typ": kind,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
        "jti": secrets.token_hex(12),
    }
    return jwt.encode(payload, _secret(), algorithm=current_app.config["JWT_ALGORITHM"])


def decode_token(token: str | None, expected: str = "access") -> User | None:
    if not token:
        return None
    try:
        payload = jwt.decode(
            token,
            _secret(),
            algorithms=[current_app.config["JWT_ALGORITHM"]],
            options={"require": ["exp", "iat", "sub", "typ"]},
        )
    except (JWTError, ValueError):
        return None
    if payload.get("typ") != expected or not str(payload.get("sub", "")).isdigit():
        return None
    user = db.session.get(User, int(payload["sub"]))
    if not user or not user.active or user.is_locked:
        return None
    return user


def token_from_request() -> str | None:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header.split(None, 1)[1].strip()
    return request.cookies.get(COOKIE_ACCESS)


def issue_tokens(response, user: User):
    """Escribe access + refresh + CSRF en la respuesta."""
    secure = current_app.config["COOKIE_SECURE"]
    common = dict(httponly=True, secure=secure, samesite="Strict", path="/")
    response.set_cookie(
        COOKIE_ACCESS,
        create_token(user, "access"),
        max_age=current_app.config["ACCESS_TTL_MINUTES"] * 60,
        **common,
    )
    response.set_cookie(
        COOKIE_REFRESH,
        create_token(user, "refresh"),
        max_age=current_app.config["REFRESH_TTL_DAYS"] * 24 * 3600,
        secure=secure,
        httponly=True,
        samesite="Strict",
        path="/api/auth/refresh",
    )
    ensure_csrf_cookie(response)
    return response


def clear_tokens(response):
    response.delete_cookie(COOKIE_ACCESS, path="/")
    response.delete_cookie(COOKIE_REFRESH, path="/api/auth/refresh")
    response.delete_cookie(COOKIE_CSRF, path="/")
    return response


def ensure_csrf_cookie(response):
    if not request.cookies.get(COOKIE_CSRF):
        response.set_cookie(
            COOKIE_CSRF,
            secrets.token_urlsafe(24),
            httponly=False,
            secure=current_app.config["COOKIE_SECURE"],
            samesite="Strict",
            max_age=current_app.config["REFRESH_TTL_DAYS"] * 24 * 3600,
            path="/",
        )
    return response


# --------------------------------------------------------------------------- #
# Decoradores
# --------------------------------------------------------------------------- #
def _is_api_request() -> bool:
    return request.path.startswith("/api/") or request.path.startswith("/lab/")


def require_auth(roles: tuple[str, ...] | None = None):
    """Exige un access token válido y, opcionalmente, uno de los roles dados."""

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = decode_token(token_from_request(), "access")
            if user is None:
                if _is_api_request():
                    return jsonify(error="Sesión expirada o inválida"), 401
                return redirect("/login?reason=expired")
            g.current_user = user
            if roles and user.role not in roles:
                audit(
                    "acceso_denegado",
                    f"Ruta {request.path} requiere {','.join(roles)}; rol real: {user.role}",
                    "warn",
                )
                if _is_api_request():
                    return jsonify(error="No tienes permisos para esta acción"), 403
                return _render_forbidden()
            return view(*args, **kwargs)

        return wrapper

    return decorator


def _render_forbidden():
    from flask import render_template

    return render_template("error.html", code=403, title="Acceso denegado",
                           message="Tu rol no tiene permisos para abrir esta sección."), 403


def require_csrf(view):
    """Doble envío: la cookie psw_csrf debe coincidir con la cabecera/formulario."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        # GET/HEAD/OPTIONS no modifican estado: no requieren token.
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return view(*args, **kwargs)
        cookie = request.cookies.get(COOKIE_CSRF, "")
        body = request.get_json(silent=True) or {}
        supplied = (
            request.headers.get("X-CSRF-Token")
            or request.form.get("csrf_token")
            or body.get("csrf_token", "")
        )
        if not cookie or not supplied or not hmac.compare_digest(cookie, str(supplied)):
            audit("csrf_rechazado", f"Petición {request.method} {request.path} sin CSRF válido", "warn")
            return jsonify(error="Token CSRF inválido o ausente"), 403
        return view(*args, **kwargs)

    return wrapper


# --------------------------------------------------------------------------- #
# Auditoría y protección de login
# --------------------------------------------------------------------------- #
def audit(action: str, detail: str = "", severity: str = "info", user_id: int | None = None) -> None:
    user = getattr(g, "current_user", None)
    try:
        db.session.add(
            AuditLog(
                user_id=user_id if user_id is not None else (user.id if user else None),
                username=user.username if user else "anónimo",
                action=action[:64],
                detail=detail[:1000],
                ip=request.remote_addr or "",
                severity=severity,
            )
        )
        db.session.commit()
    except Exception:  # pragma: no cover - la auditoría nunca debe romper la petición
        db.session.rollback()


def register_failed_attempt(username: str, ip: str) -> None:
    key = f"{ip}:{username.lower()}"
    with _attempts_lock:
        rec = _attempts.get(key, {"n": 0, "reset": time.time() + 900})
        if time.time() > rec["reset"]:
            rec = {"n": 0, "reset": time.time() + 900}
        rec["n"] += 1
        _attempts[key] = rec


def too_many_attempts(username: str, ip: str, limit: int = 12) -> bool:
    key = f"{ip}:{username.lower()}"
    with _attempts_lock:
        rec = _attempts.get(key)
        return bool(rec and rec["n"] >= limit and rec["reset"] > time.time())


def reset_attempts(username: str, ip: str) -> None:
    _attempts.pop(f"{ip}:{username.lower()}", None)


def safe_next(value: str | None) -> str:
    """Sólo rutas relativas locales: evita redirecciones abiertas."""
    if not value or not isinstance(value, str):
        return ""
    if not value.startswith("/") or value.startswith("//") or "\\" in value or "\n" in value:
        return ""
    return value
