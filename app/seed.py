"""Datos de demostración. Idempotente: no duplica nada si ya existe la BD."""

from datetime import timedelta

from .extensions import db
from .models import AuditLog, Course, Enrollment, User, utcnow

USERS = [
    ("admin", "ana.admin@academia.demo", "Ana Salazar", "admin", "Admin123*"),
    ("docente", "luis.docente@academia.demo", "Luis Ramírez", "docente", "Profe123*"),
    ("estudiante", "mia.estudiante@academia.demo", "Mía Torres", "estudiante", "Alumno123*"),
    ("jcastillo", "jorge.castillo@academia.demo", "Jorge Castillo", "estudiante", "Alumno123*"),
    ("pgonzalez", "paola.gonzalez@academia.demo", "Paola González", "estudiante", "Alumno123*"),
    ("dmoreno", "diego.moreno@academia.demo", "Diego Moreno", "estudiante", "Alumno123*"),
    ("srojas", "sofia.rojas@academia.demo", "Sofía Rojas", "estudiante", "Alumno123*"),
    ("hvega", "hugo.vega@academia.demo", "Hugo Vega", "estudiante", "Alumno123*"),
    ("cmendoza", "camila.mendoza@academia.demo", "Camila Mendoza", "estudiante", "Alumno123*"),
]

COURSES = [
    ("PSW-101", "Programación Segura Web", "Lun 08:00 - 10:00", "A-204",
     "Diseño de aplicaciones web con controles OWASP desde el inicio."),
    ("OWASP-210", "Fundamentos OWASP Top 10", "Mar 14:00 - 16:00", "B-101",
     "Análisis de las diez vulnerabilidades críticas más frecuentes."),
    ("PED-305", "Pruebas de Penetración", "Mié 09:00 - 11:00", "Lab-3",
     "Metodologías de scanning, explotación controlada y reportes."),
    ("CRIP-220", "Criptografía Aplicada", "Jue 16:00 - 18:00", "A-305",
     "Hashing, cifrado, tokens y gestión de secretos."),
    ("QA-180", "Calidad y Pruebas Automatizadas", "Vie 10:00 - 12:00", "Lab-1",
     "Selenium, Playwright y pruebas funcionales continuas."),
    ("RED-240", "Redes y Configuración Segura", "Vie 14:00 - 16:00", "B-202",
     "Cabeceras HTTP, TLS, segmentación y endurecimiento de servicios."),
]


def seed_database() -> None:
    if User.query.first() is not None:
        return

    users = {}
    for username, email, name, role, password in USERS:
        user = User(username=username, email=email, full_name=name, role=role)
        user.set_password(password)
        db.session.add(user)
        users[username] = user
    db.session.flush()

    teacher = users["docente"]
    courses = []
    for code, name, schedule, classroom, description in COURSES:
        course = Course(code=code, name=name, schedule=schedule, classroom=classroom,
                        description=description, teacher_id=teacher.id)
        db.session.add(course)
        courses.append(course)
    db.session.flush()

    grades = [18, 16, 14, 17, 12, 15, 19, 13, 11]
    idx = 0
    for course in courses:
        for username in ("estudiante", "jcastillo", "pgonzalez", "dmoreno"):
            grade = grades[idx % len(grades)] if idx % 3 else None
            db.session.add(Enrollment(student_id=users[username].id, course_id=course.id, grade=grade))
            idx += 1

    now = utcnow()
    for action, detail, severity, minutes in [
        ("login_ok", "Inicio de sesión del administrador", "info", 35),
        ("login_ok", "Inicio de sesión del docente", "info", 28),
        ("curso_creado", "Curso PSW-101 actualizado", "info", 22),
        ("acceso_denegado", "Rol estudiante intentó abrir /app/usuarios", "warn", 12),
        ("csrf_rechazado", "Petición POST sin cabecera X-CSRF-Token", "warn", 6),
    ]:
        db.session.add(AuditLog(username="sistema", action=action, detail=detail,
                                severity=severity, ip="127.0.0.1",
                                timestamp=now - timedelta(minutes=minutes)))

    db.session.commit()
