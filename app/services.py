"""Consultas compartidas entre páginas y API."""

from sqlalchemy import func

from .extensions import db
from .models import AuditLog, Course, Enrollment, User


def visible_courses(user: User) -> list[Course]:
    query = Course.query
    if user.role == "estudiante":
        query = query.join(Enrollment, Enrollment.course_id == Course.id).filter(
            Enrollment.student_id == user.id
        )
    return query.order_by(Course.code).all()


def dashboard_stats(user: User) -> dict:
    courses = visible_courses(user)
    course_ids = [c.id for c in courses]
    if user.role == "estudiante":
        enrollments = Enrollment.query.filter(Enrollment.student_id == user.id).all()
        students = {e.student_id for e in enrollments}
    elif user.role == "docente":
        enrollments = (
            Enrollment.query.join(Course, Enrollment.course_id == Course.id)
            .filter(Course.teacher_id == user.id)
            .all()
        )
        students = {e.student_id for e in enrollments}
    else:
        enrollments = Enrollment.query.all()
        students = {e.student_id for e in enrollments}

    grades = [e.grade for e in enrollments if e.grade is not None]
    avg = round(sum(grades) / len(grades), 1) if grades else 0

    warnings = AuditLog.query.filter(AuditLog.severity.in_(["warn", "error"])).count()
    return {
        "cursos": len(courses),
        "estudiantes": len(students),
        "promedio": avg,
        "alertas": warnings,
        "course_ids": course_ids,
    }


def recent_audit(limit: int = 6) -> list[AuditLog]:
    return AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(limit).all()


def distribution() -> list[dict]:
    rows = (
        db.session.query(User.role, func.count(User.id))
        .group_by(User.role)
        .order_by(User.role)
        .all()
    )
    total = sum(count for _, count in rows) or 1
    labels = {"admin": "Administradores", "docente": "Docentes", "estudiante": "Estudiantes"}
    return [
        {"label": labels.get(role, role), "count": count, "pct": round(count * 100 / total)}
        for role, count in rows
    ]
