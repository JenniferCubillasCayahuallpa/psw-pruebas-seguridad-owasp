"""Pruebas unitarias de los controles de seguridad (pytest).

    pytest tests/test_seguridad.py -v
"""

import os

import pytest

os.environ.setdefault("LAB_MODE", "1")

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import User  # noqa: E402
from app.security import safe_next  # noqa: E402


@pytest.fixture(scope="module")
def app():
    application = create_app()
    application.config.update(TESTING=True)
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username="admin", password="Admin123*"):
    client.get("/login")
    csrf = client.get_cookie("psw_csrf").value
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200, response.get_json()
    return response


def csrf(client):
    return client.get_cookie("psw_csrf").value


def test_cabeceras_de_seguridad_en_paginas_publicas(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "strict-origin-when-cross-origin" in response.headers["Referrer-Policy"]


def test_login_entrega_cookies_httponly(client):
    login(client)
    access = client.get_cookie("psw_access")
    refresh = client.get_cookie("psw_refresh", path="/api/auth/refresh")
    assert access and access.http_only
    assert refresh and refresh.http_only
    assert access.path == "/"
    assert refresh.path == "/api/auth/refresh"


def test_escrituras_requieren_csrf(client):
    login(client)
    response = client.post("/api/cursos", json={"code": "ZZZ-999", "name": "Sin token"})
    assert response.status_code == 403
    assert "CSRF" in response.get_json()["error"]


def test_rbac_bloquea_estudiante_en_administracion(app):
    student = app.test_client()
    login(student, "estudiante", "Alumno123*")
    assert student.get("/app/usuarios").status_code == 403
    assert student.get("/api/usuarios").status_code == 403
    assert student.get("/app/cursos").status_code == 200


def test_contrasenas_no_estan_en_texto_plano(app):
    with app.app_context():
        user = db.session.get(User, 1)
        assert user.password_hash != "Admin123*"
        assert user.password_hash.startswith("$2b$")
        assert user.check_password("Admin123*")


def test_token_manipulado_se_rechaza(client):
    login(client)
    token = client.get_cookie("psw_access").value
    tampered = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
    client.set_cookie("psw_access", tampered, domain="localhost")
    response = client.get("/api/me")
    assert response.status_code == 401


def test_mensaje_generico_no_revela_usuario(client):
    client.get("/login")
    token = csrf(client)
    unknown = client.post("/api/auth/login", json={"username": "noexiste", "password": "x"},
                          headers={"X-CSRF-Token": token})
    known = client.post("/api/auth/login", json={"username": "admin", "password": "mala"},
                        headers={"X-CSRF-Token": token})
    assert unknown.status_code == known.status_code == 401
    assert unknown.get_json()["error"] == known.get_json()["error"]


def test_xss_corregido_escapa_payload(client):
    payload = "<script>alert(1)</script>"
    response = client.get("/lab/buscar_seguro", query_string={"q": payload})
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.get_data(as_text=True)
    assert "&lt;script&gt;" in response.get_data(as_text=True)


def test_sqli_corregido_no_hace_bypass(client):
    client.get("/login")
    response = client.post(
        "/lab/login_seguro",
        data={"username": "' OR 1=1 --", "password": "x"},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert response.status_code == 200
    assert "Usuario o contraseña incorrectos" in response.get_data(as_text=True)
    assert "ACCESO CONCEDIDO" not in response.get_data(as_text=True)


def test_rutas_vulnerables_no_existen_en_modo_seguro(app):
    # El modo seguro se comprueba con una configuración derivada en una app aparte.
    from app.config import Config

    class SafeConfig(Config):
        LAB_MODE = False

    safe = create_app(SafeConfig)
    assert safe.test_client().get("/lab/buscar?q=hola").status_code == 404


def test_safe_next_bloquea_redirecciones_abiertas():
    assert safe_next("//evil.test") == ""
    assert safe_next("https://evil.test") == ""
    assert safe_next("javascript:alert(1)") == ""
    assert safe_next("/app/cursos") == "/app/cursos"
