"""Punto de entrada del portal.

  python run.py              -> modo seguro (recomendado)
  python run.py --lab        -> expone el laboratorio vulnerable para las prácticas
  python run.py --lab --port 5000
"""

import argparse
import os

from dotenv import load_dotenv

load_dotenv()


def main() -> None:
    parser = argparse.ArgumentParser(description="Portal Docente Seguro (PSW · OWASP)")
    parser.add_argument("--lab", action="store_true", help="Activar endpoints vulnerables de demostración")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "5000")))
    parser.add_argument("--debug", action="store_true", help="Sólo para desarrollo local")
    args = parser.parse_args()

    if args.lab:
        os.environ["LAB_MODE"] = "1"
    else:
        os.environ.setdefault("LAB_MODE", "0")

    from app import create_app

    app = create_app()
    print("\n" + "=" * 66)
    print("  AulaSegura · Portal Docente Seguro")
    print(f"  URL      : http://{args.host}:{args.port}")
    print(f"  LAB_MODE : {'1 (vulnerable a propósito)' if app.config['LAB_MODE'] else '0 (seguro)'}")
    print("  Cuentas  : admin/Admin123* · docente/Profe123* · estudiante/Alumno123*")
    print("=" * 66 + "\n")
    app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)


if __name__ == "__main__":
    main()
