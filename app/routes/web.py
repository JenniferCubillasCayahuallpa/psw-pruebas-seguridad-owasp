"""Páginas del portal (renderizado en servidor, sin HTML dinámico en el cliente)."""

from flask import Blueprint, current_app, g, render_template

from ..models import Course, Enrollment, User
from ..security import require_auth
from ..services import dashboard_stats, distribution, recent_audit, visible_courses

bp = Blueprint("web", __name__)


@bp.get("/")
def landing():
    return render_template("landing.html")


@bp.get("/app")
@require_auth()
def dashboard():
    return render_template(
        "dashboard.html",
        stats=dashboard_stats(g.current_user),
        distribucion=distribution(),
        auditoria=recent_audit(5),
    )


@bp.get("/app/cursos")
@require_auth()
def cursos():
    return render_template(
        "cursos.html",
        cursos=visible_courses(g.current_user),
        puede_crear=g.current_user.role in ("admin", "docente"),
        inscritos={e.course_id for e in g.current_user.enrollments},
    )


@bp.get("/app/estudiantes")
@require_auth(("admin", "docente"))
def estudiantes():
    estudiantes = User.query.filter_by(role="estudiante").order_by(User.full_name).all()
    cursos = Course.query.order_by(Course.code).all()
    inscripciones = Enrollment.query.all()
    return render_template("estudiantes.html", estudiantes=estudiantes, cursos=cursos,
                           inscripciones=inscripciones)


@bp.get("/app/usuarios")
@require_auth(("admin",))
def usuarios():
    return render_template("usuarios.html",
                           usuarios=User.query.order_by(User.role, User.username).all())


@bp.get("/app/auditoria")
@require_auth(("admin",))
def auditoria():
    from ..models import AuditLog

    return render_template("auditoria.html", eventos=AuditLog.query
                           .order_by(AuditLog.timestamp.desc()).limit(100).all())


@bp.get("/app/laboratorio")
@require_auth()
def laboratorio():
    return render_template("laboratorio.html", lab_mode=current_app.config["LAB_MODE"])
