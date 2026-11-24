"""Autenticación: login, refresh, logout y página de acceso."""

from datetime import timedelta

from flask import Blueprint, g, jsonify, make_response, redirect, render_template, request

from ..extensions import db
from ..models import User, utcnow
from ..security import (
    audit,
    clear_tokens,
    decode_token,
    ensure_csrf_cookie,
    issue_tokens,
    register_failed_attempt,
    reset_attempts,
    safe_next,
    token_from_request,
    too_many_attempts,
    require_csrf,
)

bp = Blueprint("auth", __name__)

GENERIC_ERROR = "Usuario o contraseña incorrectos"


@bp.get("/login")
def login_page():
    if decode_token(token_from_request(), "access"):
        return redirect("/app")
    nxt = safe_next(request.args.get("next"))
    response = make_response(
        render_template("login.html", next=nxt, reason=request.args.get("reason", ""))
    )
    return ensure_csrf_cookie(response)


@bp.post("/api/auth/login")
@require_csrf
def api_login():
    data = request.get_json(silent=True) or {}
    identifier = str(data.get("username") or "").strip().lower()[:120]
    password = str(data.get("password") or "")
    ip = request.remote_addr or ""

    if not identifier or not password:
        return jsonify(error="Completa usuario y contraseña"), 400

    if too_many_attempts(identifier, ip):
        audit("rate_limit", f"Intentos bloqueados para {identifier}", "warn")
        return jsonify(error="Demasiados intentos. Vuelve a intentar en 15 minutos."), 429

    user = User.query.filter_by(username=identifier).first() or User.query.filter_by(email=identifier).first()
    if user is None:
        register_failed_attempt(identifier, ip)
        audit("login_fallido", f"Usuario inexistente: {identifier}", "warn")
        return jsonify(error=GENERIC_ERROR), 401

    if user.is_locked:
        return jsonify(error="Cuenta bloqueada temporalmente. Contacta al administrador."), 423

    if not user.check_password(password):
        user.failed_attempts += 1
        if user.failed_attempts >= 5:
            user.locked_until = utcnow() + timedelta(minutes=15)
            user.failed_attempts = 0
        db.session.commit()
        register_failed_attempt(identifier, ip)
        audit("login_fallido", f"Contraseña incorrecta para {identifier}", "warn", user.id)
        return jsonify(error=GENERIC_ERROR), 401

    if not user.active:
        return jsonify(error="Cuenta desactivada. Contacta al administrador."), 403

    user.failed_attempts = 0
    user.locked_until = None
    db.session.commit()
    g.current_user = user
    audit("login_ok", f"Inicio de sesión correcto ({user.role})", "info", user.id)
    reset_attempts(identifier, ip)

    destination = safe_next(data.get("next")) or "/app"
    response = make_response(
        jsonify(ok=True, redirect=destination, user=user.to_dict(include_contact=True))
    )
    return issue_tokens(response, user)


@bp.post("/api/auth/refresh")
@require_csrf
def api_refresh():
    refresh = request.cookies.get("psw_refresh")
    user = decode_token(refresh, "refresh")
    if user is None:
        return jsonify(error="Refresh token inválido o expirado"), 401
    g.current_user = user
    audit("token_refresh", "Access token renovado", "info", user.id)
    response = make_response(jsonify(ok=True))
    return issue_tokens(response, user)


@bp.post("/api/auth/logout")
@require_csrf
def api_logout():
    user = getattr(g, "current_user", None)
    if user:
        audit("logout", "Cierre de sesión", "info", user.id)
    response = make_response(jsonify(ok=True, redirect="/login"))
    return clear_tokens(response)


@bp.get("/logout")
def logout_page():
    """Atajo navegable; no cambia estado del servidor, sólo limpia cookies."""
    response = redirect("/login")
    return clear_tokens(response)


@bp.get("/api/auth/me")
def api_me():
    user = decode_token(token_from_request(), "access")
    if user is None:
        return jsonify(error="No autenticado"), 401
    return jsonify(user=user.to_dict(include_contact=True))
