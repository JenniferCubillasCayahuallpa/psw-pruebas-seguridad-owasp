"""API JSON protegida con JWT, CSRF y RBAC."""

import re

from flask import Blueprint, g, jsonify, request

from ..extensions import db
from ..models import AuditLog, Course, Enrollment, User, utcnow
from ..security import audit, require_auth, require_csrf
from ..services import dashboard_stats, distribution, recent_audit, visible_courses

bp = Blueprint("api", __name__, url_prefix="/api")

CODE_RE = re.compile(r"^[A-Za-z0-9-]{3,24}$")


@bp.get("/me")
@require_auth()
def me():
    return jsonify(user=g.current_user.to_dict(include_contact=True))


@bp.get("/stats")
@require_auth()
def stats():
    return jsonify(dashboard_stats(g.current_user))


@bp.get("/cursos")
@require_auth()
def cursos():
    return jsonify(cursos=[c.to_dict() for c in visible_courses(g.current_user)])


@bp.post("/cursos")
@require_auth(("admin", "docente"))
@require_csrf
def crear_curso():
    data = request.get_json(silent=True) or {}
    code = str(data.get("code") or "").strip().upper()
    name = str(data.get("name") or "").strip()
    schedule = str(data.get("schedule") or "").strip()
    classroom = str(data.get("classroom") or "").strip()
    description = str(data.get("description") or "").strip()

    if not CODE_RE.fullmatch(code):
        return jsonify(error="El código debe tener 3 a 24 letras, números o guiones"), 400
    if not 4 <= len(name) <= 120:
        return jsonify(error="El nombre debe tener entre 4 y 120 caracteres"), 400
    if Course.query.filter_by(code=code).first():
        return jsonify(error="Ya existe un curso con ese código"), 409

    course = Course(code=code, name=name[:120], schedule=schedule[:80],
                    classroom=classroom[:40], description=description[:800],
                    teacher_id=g.current_user.id if g.current_user.role == "docente" else 2)
    db.session.add(course)
    db.session.commit()
    audit("curso_creado", f"Curso {code} creado por {g.current_user.username}", "info")
    return jsonify(ok=True, curso=course.to_dict()), 201


@bp.post("/cursos/<int:course_id>/inscribir")
@require_auth(("estudiante",))
@require_csrf
def inscribir(course_id: int):
    course = db.session.get(Course, course_id)
    if course is None:
        return jsonify(error="Curso inexistente"), 404
    if Enrollment.query.filter_by(student_id=g.current_user.id, course_id=course_id).first():
        return jsonify(error="Ya estás inscrito en este curso"), 409
    db.session.add(Enrollment(student_id=g.current_user.id, course_id=course_id))
    db.session.commit()
    audit("inscripcion", f"{g.current_user.username} se inscribió en {course.code}", "info")
    return jsonify(ok=True), 201


@bp.post("/inscripciones/<int:enrollment_id>/calificacion")
@require_auth(("admin", "docente"))
@require_csrf
def calificar(enrollment_id: int):
    enrollment = db.session.get(Enrollment, enrollment_id)
    if enrollment is None:
        return jsonify(error="Inscripción inexistente"), 404
    try:
        grade = int((request.get_json(silent=True) or {}).get("grade"))
    except (TypeError, ValueError):
        return jsonify(error="La calificación debe ser un número entero"), 400
    if not 0 <= grade <= 20:
        return jsonify(error="La calificación debe estar entre 0 y 20"), 400
    enrollment.grade = grade
    db.session.commit()
    audit("calificacion", f"Nota {grade} registrada en inscripción #{enrollment_id}", "info")
    return jsonify(ok=True, grade=grade)


@bp.get("/estudiantes")
@require_auth(("admin", "docente"))
def estudiantes():
    q = str(request.args.get("q") or "").strip()[:60]
    query = User.query.filter(User.role == "estudiante")
    if q:
        query = query.filter(User.full_name.ilike(f"%{q}%"))
    return jsonify(estudiantes=[u.to_dict(include_contact=True) for u in query.order_by(User.full_name).all()])


@bp.get("/calificaciones")
@require_auth(("admin", "docente"))
def calificaciones():
    query = Enrollment.query
    course_id = request.args.get("course_id", type=int)
    if course_id:
        query = query.filter(Enrollment.course_id == course_id)
    return jsonify(calificaciones=[e.to_dict() for e in query.order_by(Enrollment.id).limit(200).all()])


@bp.get("/usuarios")
@require_auth(("admin",))
def usuarios():
    return jsonify(usuarios=[u.to_dict(include_contact=True)
                             for u in User.query.order_by(User.role, User.username).all()])


@bp.post("/usuarios")
@require_auth(("admin",))
@require_csrf
def crear_usuario():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username") or "").strip().lower()
    email = str(data.get("email") or "").strip().lower()
    full_name = str(data.get("full_name") or "").strip()
    role = str(data.get("role") or "")
    password = str(data.get("password") or "")

    if role not in {"admin", "docente", "estudiante"}:
        return jsonify(error="Rol no válido"), 400
    if not re.fullmatch(r"[a-z0-9._-]{3,32}", username):
        return jsonify(error="Usuario: 3-32 letras minúsculas, números, punto, guion o guion bajo"), 400
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", email) or len(email) > 120:
        return jsonify(error="Correo electrónico no válido"), 400
    if len(full_name) < 4 or len(full_name) > 120:
        return jsonify(error="Nombre no válido"), 400
    if len(password) < 10:
        return jsonify(error="La contraseña debe tener al menos 10 caracteres"), 400
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify(error="El usuario o correo ya existe"), 409

    user = User(username=username, email=email, full_name=full_name[:120], role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    audit("usuario_creado", f"Usuario {username} creado con rol {role}", "info")
    return jsonify(ok=True, usuario=user.to_dict(include_contact=True)), 201


@bp.get("/auditoria")
@require_auth(("admin",))
def auditoria():
    return jsonify(auditoria=[entry.to_dict() for entry in AuditLog.query
                              .order_by(AuditLog.timestamp.desc()).limit(150).all()])


@bp.get("/distribucion")
@require_auth()
def distribucion():
    return jsonify(distribucion=distribution())
