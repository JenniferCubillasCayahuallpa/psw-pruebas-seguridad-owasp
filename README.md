# AulaSegura · Pruebas funcionales y seguridad OWASP (PSW)

Mini proyecto académico: portal docente con **backend Python/Flask**, frontend propio y **tres roles**
(administrador, docente y estudiante). Incluye autenticación con **JWT**, protección **CSRF**, **RBAC**,
un laboratorio controlado de vulnerabilidades OWASP, pruebas funcionales con **Selenium** y un
**informe con capturas reales** de cada hallazgo.

> El modo **seguro** es el predeterminado. Las rutas vulnerables sólo existen al ejecutar con `--lab`.

---

## 1. Puesta en marcha

```bash
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. (Opcional) configurar secretos y modo
copy .env.example .env        # Windows
# cp .env.example .env        # Linux / macOS

# 3. Ejecutar en modo seguro
python run.py

# 3b. Ejecutar en modo laboratorio (para las prácticas)
python run.py --lab
```

Abrir **http://127.0.0.1:5000**.

### Cuentas de demostración (3 roles)

| Rol | Usuario | Contraseña | Permisos |
| --- | --- | --- | --- |
| Administrador | `admin` | `Admin123*` | Usuarios, auditoría, todo lo demás |
| Docente | `docente` | `Profe123*` | Cursos, estudiantes, calificaciones |
| Estudiante | `estudiante` | `Alumno123*` | Ver cursos e inscribirse |

---

## 2. Ejecutar todo (recomendado)

```bash
python scripts/ejecutar_pruebas.py
```

El orquestador:

1. Levanta la app con `LAB_MODE=1`.
2. Ejecuta `tests/selenium_funcional.py`: login → panel → crear curso → verificar → logout → RBAC 403.
3. Ejecuta `scripts/capturar_evidencias.py`: recorre los seis vectores y guarda **PNGs reales**.
4. Ejecuta `scripts/generar_reporte.py`: crea el informe Markdown/HTML con las capturas incrustadas.
5. Captura el informe generado y lo deja servible en `/static/evidencias/informe.html`.

### Salidas

| Archivo | Contenido |
| --- | --- |
| `reports/selenium/resultado.json` | Resultado paso a paso de la prueba funcional. |
| `reports/selenium/*.png` | Capturas del flujo funcional. |
| `reports/capturas/*.png` | Capturas de los seis hallazgos y del control RBAC. |
| `reports/evidencias.json` | Códigos HTTP y cabeceras de cada verificación. |
| `reports/informe_seguridad.md` / `.html` | Informe completo. |
| `app/static/evidencias/informe.html` | Informe visible desde el laboratorio. |

Pruebas unitarias de seguridad adicionales:

```bash
pytest tests/test_seguridad.py -v
```

Escaneo con ZAP (requiere ZAP con API activa). Ya se ejecutó con ZAP 2.17.0 y guardó 46 alertas
relevantes en `reports/zap_alerts.json`; el informe incluye el resumen y una captura de la GUI:

```powershell
# ZAP con API en el puerto 8090
cd C:\Users\Ale\AppData\Local\ZAP\ZAP_2.17.0
.\zap.bat -host 127.0.0.1 -port 8090 -config api.key=pswlab2026
# En otra terminal, desde la carpeta del proyecto:
python scripts/zap_baseline.py --url http://127.0.0.1:5000 --api-key pswlab2026
```

---

## 3. Hallazgos del laboratorio

| ID | Vulnerabilidad | OWASP 2021 | Severidad | Ruta |
| --- | --- | --- | --- | --- |
| OWASP-01 | XSS reflejado | A03 Inyección | Alta | `/lab/buscar?q=` |
| OWASP-02 | Inyección SQL + error detallado | A03 Inyección | Crítica | `/lab/login_sqli` |
| OWASP-03 | IDOR | A01 Control de acceso | Alta | `/lab/perfil?id=` |
| OWASP-04 | CSRF por GET | A01 Control de acceso | Media | `/lab/cambiar_rol` |
| OWASP-05 | Cabeceras de seguridad ausentes | A05 Configuración | Media | `/lab/sin_headers` |
| OWASP-06 | Fuga de información en errores | A05 Configuración | Media | `/lab/error` |

Cada una tiene su versión corregida (`/lab/*_seguro` o las rutas normales del portal) y su evidencia
en `reports/informe_seguridad.html`.

---

## 4. Seguridad implementada

- **Token**: access JWT HS256 (15 min) + refresh (7 días), cookies HttpOnly, Secure configurable, SameSite=Strict.
- **Contraseñas**: bcrypt con salt; bloqueo temporal tras 5 fallos y límite de intentos por IP.
- **CSRF**: token de doble envío (`psw_csrf` + `X-CSRF-Token`) en todas las escrituras.
- **RBAC**: tres roles verificados en rutas web y API; comprobación de propiedad en perfiles.
- **Inyección**: SQLAlchemy ORM y validación de entradas; escape de salida con Jinja/MarkupSafe.
- **Cabeceras**: CSP estricta, `nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP, `no-store`.
- **Errores y auditoría**: manejadores genéricos sin trazas; registro de accesos, denegaciones y eventos.
- **Redirecciones**: `safe_next()` bloquea open redirects.

---

## 5. Estructura

```
app/
  __init__.py            fábrica Flask, cabeceras y manejadores de error
  config.py              secretos y modos
  models.py              User / Course / Enrollment / AuditLog
  security.py            JWT, CSRF, RBAC, auditoría, rate limit
  routes/                auth, web, api, lab
  templates/             base, login, landing, dashboard, cursos, estudiantes,
                         usuarios, auditoria, laboratorio, error, sprite de iconos
  static/                css/styles.css, js/app.js, icons.svg, evidencias/
tests/
  selenium_funcional.py  prueba funcional automatizada
  test_seguridad.py      pruebas unitarias de controles
scripts/
  ejecutar_pruebas.py    orquestador
  capturar_evidencias.py capturas con Selenium + datos HTTP
  generar_reporte.py     Markdown + HTML
  zap_baseline.py        escaneo opcional con ZAP
reports/                 evidencias, capturas e informe
docs/                    arquitectura, comparativa y guion de vídeo
```

---

## 6. Cobertura de la consigna

| Requisito | Dónde está |
| --- | --- |
| Script Selenium (abrir, llenar, clic, validar) | `tests/selenium_funcional.py` |
| Comparativa Playwright vs Selenium | `docs/comparativa_playwright_selenium.md` |
| Análisis ZAP / Burp | `scripts/zap_baseline.py` + `reports/informe_seguridad.md` |
| Informe con capturas, interpretación y prevención | `reports/informe_seguridad.html` y capturas |
| Documentación en vídeo con cámara + 4 conclusiones | `docs/guia_video.md` |
| 3 roles, token y máxima seguridad | `app/models.py`, `app/security.py`, `app/routes/` |

---

## 7. Cuatro conclusiones

1. **Las pruebas funcionales automatizadas son una red de seguridad frente a regresiones:** repetir el
   flujo de acceso, creación de cursos y permisos con Selenium confirma que la aplicación sigue haciendo
   lo que promete tras cada cambio, y deja evidencia reproducible.
2. **La seguridad se diseña desde el inicio y por capas:** escapar la salida, añadir CSP, firmar tokens,
   hashear contraseñas y verificar roles al mismo tiempo reduce la superficie de ataque mucho más que
   corregir una sola vulnerabilidad al final.
3. **Los escáneres aceleran la detección pero no sustituyen el criterio humano:** hay que interpretar cada
   alerta, descartar falsos positivos, entender el impacto real y volver a probar la versión corregida.
4. **Un informe claro y con capturas convierte un hallazgo técnico en una decisión:** permite priorizar
   por severidad, asignar responsables, cumplir buenas prácticas y formar una cultura de calidad y
   seguridad web.

---

## 8. Aviso

El laboratorio es un entorno **académico y aislado**. No actives `LAB_MODE=1` en un servidor público.
Antes de desplegar: genera secretos aleatorios nuevos, usa HTTPS (`COOKIE_SECURE=1`), desactiva el
laboratorio y rota cualquier credencial de demostración.
