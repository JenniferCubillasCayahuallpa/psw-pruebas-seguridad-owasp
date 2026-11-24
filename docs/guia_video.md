# Guion para la documentación en vídeo (cámara activa)

**Duración sugerida:** 6-8 minutos. **Formato:** pantalla compartida + cámara activa (esquina superior).
**Entregable:** un vídeo (MP4) y este guion como apoyo.

## Minuto 0:00-0:45 · Presentación

> "Hola, mi nombre es ____. En este vídeo presento el mini proyecto de la asignatura PSW: un portal
> docente con backend en Python/Flask, frontend propio y tres roles —administrador, docente y
> estudiante—. El objetivo es doble: automatizar una prueba funcional con Selenium y realizar un
> análisis básico de seguridad siguiendo OWASP Top 10, dejando evidencias con capturas reales."

Mostrar en pantalla: `run.py`, estructura de carpetas y el README.

## Minuto 0:45-2:00 · Construcción de la app

> "La aplicación usa autenticación con JWT: un access token de 15 minutos y un refresh token de 7 días,
> ambos en cookies HttpOnly con SameSite=Strict. Las contraseñas se guardan con bcrypt. Cada endpoint
> comprueba el rol con un decorador RBAC, y todas las escrituras exigen un token CSRF de doble envío.
> Las respuestas incluyen CSP y el resto de cabeceras de seguridad. La interfaz usa una paleta celeste,
> azul y blanco con iconos SVG locales."

Mostrar: `/login`, login como `docente/Profe123*`, panel, `/app/cursos` y `/app/laboratorio`.

## Minuto 2:00-3:30 · Prueba funcional con Selenium

> "Esta prueba abre el navegador con Chrome headless, completa el formulario, valida que el panel carga,
> crea un curso con su token CSRF, comprueba que aparece en el listado y cierra sesión. Al final verifica
> que un estudiante recibe 403 al intentar entrar en administración."

Mostrar: `tests/selenium_funcional.py` y ejecutar `python scripts/ejecutar_pruebas.py`.
Enseñar `reports/selenium/resultado.json` y las capturas `reports/selenium/*.png`.

## Minuto 3:30-5:45 · Prueba de seguridad y hallazgos

> "El modo seguro está activo por defecto. Para la práctica se activó `LAB_MODE=1`, que expone seis
> endpoints vulnerables a propósito. Ejecutamos un escaneo real con OWASP ZAP 2.17.0 sembrando esas seis
> rutas: registró 67 alertas, 46 de riesgo Low o superior, y confirmó la ausencia de CSP, cabeceras y
> tokens anti-CSRF. Cada hallazgo se verificó además con peticiones reproducibles y su captura."

Recorrer rápidamente los seis hallazgos del informe:

1. XSS reflejado en `/lab/buscar` — el payload modifica el DOM; versión corregida en `/lab/buscar_seguro`.
2. Inyección SQL en `/lab/login_sqli` — `' OR 1=1 --` concede acceso; versión ORM en `/lab/login_seguro`.
3. IDOR en `/lab/perfil?id=2` — perfil ajeno sin autenticación; versión con JWT y propiedad.
4. CSRF por GET en `/lab/cambiar_rol` — cambio de rol sin token; versión POST + JWT + CSRF.
5. Cabeceras ausentes en `/lab/sin_headers` — comparar con `/login`.
6. Error detallado en `/lab/error` — traza con secretos simulados.

Mostrar: `reports/informe_seguridad.html` con las capturas incrustadas y la tabla de severidades.

## Minuto 5:45-6:45 · Resultados

> "La prueba funcional pasó los ocho pasos. Se confirmaron seis hallazgos: una crítica, dos altas y tres
> medias. ZAP añadió 46 alertas relevantes que coinciden con los problemas de cabeceras y CSRF. Cada uno
> tiene su versión corregida y la evidencia correspondiente. Los controles preventivos de la aplicación
> —token, CSRF, bcrypt, RBAC, cabeceras y auditoría— quedaron demostrados con las pruebas unitarias de
> `tests/test_seguridad.py`."

## Minuto 6:45-7:30 · Cuatro conclusiones (leer en cámara)

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

## Checklist antes de grabar

- [ ] Cámara activa y rostro visible durante toda la grabación.
- [ ] Servidor iniciado con `python run.py --lab`.
- [ ] Informe generado y visible en `/static/evidencias/informe.html`.
- [ ] Contraseñas de demo visibles en la pantalla de acceso.
- [ ] Sin pestañas personales ni datos sensibles en el navegador.
- [ ] Volumen y encuadre comprobados.
