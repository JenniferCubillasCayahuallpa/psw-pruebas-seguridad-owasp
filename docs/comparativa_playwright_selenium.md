# Selenium vs Playwright — investigación y comparativa

## 1. Qué es cada uno

| | Selenium | Playwright |
| --- | --- | --- |
| Origen | Proyecto open source creado en 2004 (Jason Huggins), estándar de facto (W3C WebDriver). | Librería de Microsoft, publicada en 2020, sucesora espiritual de Puppeteer. |
| Modelo | Controla el navegador mediante el protocolo WebDriver (driver por navegador). | Habla directamente con Chromium/Firefox/WebKit mediante el protocolo de Chrome DevTools (CDP) y adaptadores propios. |
| Lenguajes | Java, Python, C#, JavaScript, Ruby, Kotlin, PHP. | TypeScript/JavaScript, Python, Java, .NET (y bindings de la comunidad). |
| Instalación | `pip install selenium` + driver (Selenium Manager lo descarga automáticamente desde la versión 4.6). | `pip install playwright` + `playwright install chromium` (descarga los navegadores propios). |

## 2. Diferencias clave

| Criterio | Selenium | Playwright | Impacto en este proyecto |
| --- | --- | --- | --- |
| **Rendimiento** | Cada acción pasa por el driver: mayor latencia por comando. | Comunicación directa con el motor: normalmente 2-3x más rápido en suites con muchas interacciones. | Para 7 pasos la diferencia es irrelevante; en suites grandes Playwright ahorra minutos. |
| **Esperas** | El usuario debe escribir `WebDriverWait` + condiciones explícitas. Si no, aparecen fallos intermitentes (*flaky tests*). | *Auto-waiting*: antes de hacer clic o rellenar, espera a que el elemento sea visible, estable y reciba eventos. | Menos código y menos pruebas frágiles con Playwright. |
| **Facilidad de uso** | API madura pero verbosa: `find_element(By.ID, ...)`, `send_keys`, `click`. | API más concisa: `page.get_by_role("button", name="Ingresar").click()`. Localizadores semánticos. | Playwright resulta más legible para estudiantes. |
| **Depuración** | Capturas y logs del navegador; requiere configuración adicional para vídeo/trazas. | *Trace Viewer*, vídeo, screenshots y network log integrados con `playwright show-trace`. | Gran ventaja de Playwright al documentar un proyecto en vídeo. |
| **Soporte de navegadores** | Chrome, Edge, Firefox, Safari (drivers oficiales); Safari/Linux tiene limitaciones históricas. | Chromium, Firefox y WebKit (el motor de Safari) con la misma API. | Ambos cubren lo necesario; Playwright uniformiza WebKit. |
| **Móvil / geolocalización / permisos** | Limitado; requiere Appium para móvil real. | Emulación de dispositivos, geolocalización, permisos, modo offline y grabaciones nativas. | Playwright es superior para pruebas avanzadas. |
| **Paralelismo** | Posible con Selenium Grid o Docker, pero con más configuración. | *Workers* nativos en el test runner de Playwright. | Playwright escala con menos infraestructura. |
| **Ecosistema CI** | Muy extendido; compatible con Jenkins, GitHub Actions, GitLab CI. | Cada vez más adoptado; incluye su propio runner y reportes HTML. | Ambos funcionan en CI. |
| **Curva de aprendizaje** | Mucha documentación y ejemplos; conceptos de WebDriver algo anticuados. | Documentación excelente y API coherente; requiere aceptar sus navegadores. | Selenium es más conocido en academias; Playwright es más cómodo. |

## 3. Ejemplo equivalente

**Selenium (usado en `tests/selenium_funcional.py`)**

```python
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

driver = webdriver.Chrome()
driver.get("http://127.0.0.1:5000/login")
driver.find_element(By.NAME, "username").send_keys("docente")
driver.find_element(By.NAME, "password").send_keys("Profe123*")
driver.find_element(By.CSS_SELECTOR, "#login-form button[type=submit]").click()
WebDriverWait(driver, 15).until(EC.url_contains("/app"))
```

**Playwright (alternativa investigada)**

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    page.goto("http://127.0.0.1:5000/login")
    page.get_by_placeholder("docente").fill("docente")
    page.get_by_placeholder("••••••••").fill("Profe123*")
    page.get_by_role("button", name="Ingresar al portal").click()
    page.wait_for_url("**/app")
    browser.close()
```

## 4. Decisión para este trabajo

Se implementó la prueba con **Selenium** porque es la herramienta solicitada en la consigna y porque
el flujo es corto y determinista. Las capturas se toman con `driver.save_screenshot()`.

Para un proyecto profesional o un conjunto grande de pruebas se recomendaría **Playwright**: menos
código, esperas automáticas, trazas y vídeo nativos (muy útiles para la documentación en vídeo) y
mejor rendimiento. La migración es sencilla porque los selectores y los pasos funcionales son los
mismos; sólo cambia la API de automatización.

> Fuentes consultadas: documentación oficial de [Selenium](https://www.selenium.dev/documentation/)
> y [Playwright](https://playwright.dev/python/docs/intro), y guías de migración de ambos proyectos.
