"""Modelos de dominio del portal docente."""

from datetime import datetime, timezone

import bcrypt
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint

from .extensions import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(Integer, primary_key=True)
    username = db.Column(String(64), unique=True, nullable=False, index=True)
    email = db.Column(String(120), unique=True, nullable=False)
    full_name = db.Column(String(120), nullable=False)
    password_hash = db.Column(String(120), nullable=False)
    role = db.Column(String(20), nullable=False, default="estudiante", index=True)
    active = db.Column(db.Boolean, default=True, nullable=False)
    failed_attempts = db.Column(Integer, default=0, nullable=False)
    locked_until = db.Column(DateTime, nullable=True)
    created_at = db.Column(DateTime, default=utcnow, nullable=False)

    teaching = db.relationship("Course", back_populates="teacher", foreign_keys="Course.teacher_id")
    enrollments = db.relationship("Enrollment", back_populates="student", cascade="all, delete-orphan")

    def set_password(self, plain: str) -> None:
        self.password_hash = bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def check_password(self, plain: str) -> bool:
        try:
            return bcrypt.checkpw(plain.encode("utf-8"), self.password_hash.encode("utf-8"))
        except (ValueError, TypeError):
            return False

    @property
    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > utcnow()

    @property
    def role_label(self) -> str:
        return {"admin": "Administrador", "docente": "Docente", "estudiante": "Estudiante"}.get(
            self.role, self.role
        )

    def to_dict(self, include_contact: bool = False) -> dict:
        data = {
            "id": self.id,
            "username": self.username,
            "full_name": self.full_name,
            "role": self.role,
            "role_label": self.role_label,
        }
        if include_contact:
            data["email"] = self.email
        return data


class Course(db.Model):
    __tablename__ = "courses"

    id = db.Column(Integer, primary_key=True)
    code = db.Column(String(24), unique=True, nullable=False, index=True)
    name = db.Column(String(120), nullable=False)
    schedule = db.Column(String(80), nullable=False, default="")
    classroom = db.Column(String(40), nullable=False, default="")
    description = db.Column(Text, nullable=False, default="")
    teacher_id = db.Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = db.Column(DateTime, default=utcnow, nullable=False)

    teacher = db.relationship("User", back_populates="teaching", foreign_keys=[teacher_id])
    enrollments = db.relationship("Enrollment", back_populates="course", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "code": self.code,
            "name": self.name,
            "schedule": self.schedule,
            "classroom": self.classroom,
            "description": self.description,
            "teacher": self.teacher.full_name if self.teacher else "",
            "students": len(self.enrollments),
        }


class Enrollment(db.Model):
    __tablename__ = "enrollments"
    __table_args__ = (UniqueConstraint("student_id", "course_id", name="uq_student_course"),)

    id = db.Column(Integer, primary_key=True)
    student_id = db.Column(Integer, ForeignKey("users.id"), nullable=False)
    course_id = db.Column(Integer, ForeignKey("courses.id"), nullable=False)
    grade = db.Column(Integer, nullable=True)
    created_at = db.Column(DateTime, default=utcnow, nullable=False)

    student = db.relationship("User", back_populates="enrollments")
    course = db.relationship("Course", back_populates="enrollments")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "student": self.student.full_name if self.student else "",
            "student_id": self.student_id,
            "course": self.course.name if self.course else "",
            "course_id": self.course_id,
            "grade": self.grade,
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(Integer, primary_key=True)
    timestamp = db.Column(DateTime, default=utcnow, nullable=False, index=True)
    user_id = db.Column(Integer, nullable=True)
    username = db.Column(String(64), nullable=False, default="anónimo")
    action = db.Column(String(64), nullable=False, index=True)
    detail = db.Column(Text, nullable=False, default="")
    ip = db.Column(String(64), nullable=False, default="")
    severity = db.Column(String(16), nullable=False, default="info")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "username": self.username,
            "action": self.action,
            "detail": self.detail,
            "ip": self.ip,
            "severity": self.severity,
        }
