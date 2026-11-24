"""Configuración centralizada de la aplicación.

El modo seguro es el valor por defecto. Las rutas vulnerables del laboratorio
sólo se registran cuando LAB_MODE=1 (o al ejecutar `python run.py --lab`).
"""

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-only-no-usar-en-produccion-cambiar")
    JWT_SECRET = os.getenv("JWT_SECRET", SECRET_KEY + "-jwt-cambiar")
    JWT_ALGORITHM = "HS256"

    ACCESS_TTL_MINUTES = int(os.getenv("ACCESS_TTL_MINUTES", "15"))
    REFRESH_TTL_DAYS = int(os.getenv("REFRESH_TTL_DAYS", "7"))

    _db_url = os.getenv("DATABASE_URL", "sqlite:///instance/psw_seguridad.db")
    if _db_url.startswith("sqlite:///") and not _db_url.startswith("sqlite:////"):
        _relative = _db_url[len("sqlite:///") :]
        _absolute = (BASE_DIR / _relative).resolve()
        _absolute.parent.mkdir(parents=True, exist_ok=True)
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + str(_absolute).replace("\\", "/")
    else:
        SQLALCHEMY_DATABASE_URI = _db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    LAB_MODE = _bool("LAB_MODE", "0")
    COOKIE_SECURE = _bool("COOKIE_SECURE", "0")
    FORCE_HTTPS = _bool("FORCE_HTTPS", "0")

    MAX_CONTENT_LENGTH = 256 * 1024
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
