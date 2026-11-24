"""Fábrica de la aplicación Flask del portal docente."""

from flask import Flask, g, jsonify, render_template, request

from .config import Config
from .extensions import db
from .routes import api, auth, lab, web

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def create_app(config_class=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)
    db.init_app(app)

    app.register_blueprint(auth.bp)
    app.register_blueprint(web.bp)
    app.register_blueprint(api.bp)
    if app.config["LAB_MODE"]:
        app.register_blueprint(lab.bp)
        app.logger.warning("MODO LABORATORIO ACTIVO: endpoints vulnerables expuestos a propósito")

    _register_hooks(app)
    _register_errors(app)

    with app.app_context():
        db.create_all()
        from .seed import seed_database

        seed_database()
    return app


def _register_hooks(app: Flask) -> None:
    @app.after_request
    def apply_security_headers(response):
        if not getattr(g, "skip_security_headers", False):
            for name, value in SECURITY_HEADERS.items():
                response.headers.setdefault(name, value)
            if app.config["FORCE_HTTPS"] or request.is_secure:
                response.headers.setdefault(
                    "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
                )
        if request.path.startswith(("/api/", "/app/", "/lab/")):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.before_request
    def reject_suspicious_paths():
        path = (request.path or "").lower()
        if any(token in path for token in ("../", "..\\", "%2e%2e", "\x00")):
            return jsonify(error="Ruta no permitida"), 400
        return None


def _register_errors(app: Flask) -> None:
    def wants_json() -> bool:
        return request.path.startswith(("/api/", "/lab/"))

    @app.errorhandler(400)
    def bad_request(_error):
        if wants_json():
            return jsonify(error="Petición no válida"), 400
        return render_template("error.html", code=400, title="Petición no válida",
                               message="Revisa los datos enviados."), 400

    @app.errorhandler(401)
    def unauthorized(_error):
        if wants_json():
            return jsonify(error="No autenticado"), 401
        return render_template("error.html", code=401, title="Sesión requerida",
                               message="Inicia sesión para continuar."), 401

    @app.errorhandler(403)
    def forbidden(_error):
        if wants_json():
            return jsonify(error="Acceso denegado"), 403
        return render_template("error.html", code=403, title="Acceso denegado",
                               message="Tu rol no tiene permisos para esta sección."), 403

    @app.errorhandler(404)
    def not_found(_error):
        if wants_json():
            return jsonify(error="Recurso no encontrado"), 404
        return render_template("error.html", code=404, title="Página no encontrada",
                               message="La ruta solicitada no existe."), 404

    @app.errorhandler(413)
    def too_large(_error):
        if wants_json():
            return jsonify(error="Archivo demasiado grande"), 413
        return render_template("error.html", code=413, title="Petición demasiado grande",
                               message="Reduce el tamaño de los datos enviados."), 413

    @app.errorhandler(500)
    def server_error(_error):
        # Nunca se devuelve el traceback al cliente (salvo el laboratorio, que lo simula).
        if wants_json():
            return jsonify(error="Error interno del servidor"), 500
        return render_template("error.html", code=500, title="Error interno",
                               message="Ha ocurrido un problema. Inténtalo de nuevo."), 500
