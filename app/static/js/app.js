/* Portal Docente Seguro — JavaScript sin librerías.
   Todas las peticiones de escritura envían la cabecera X-CSRF-Token. */

(function () {
  "use strict";

  function getCookie(name) {
    const prefix = name + "=";
    return document.cookie.split(";").map((c) => c.trim()).find((c) => c.startsWith(prefix))
      ? decodeURIComponent(document.cookie.split(";").map((c) => c.trim()).find((c) => c.startsWith(prefix)).slice(prefix.length))
      : "";
  }

  async function api(path, options) {
    const opts = Object.assign({ credentials: "same-origin", headers: {} }, options || {});
    opts.headers = Object.assign({}, opts.headers, {
      "X-CSRF-Token": getCookie("psw_csrf"),
      Accept: "application/json",
    });
    if (opts.body && !(opts.body instanceof FormData)) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    const response = await fetch(path, opts);
    let payload = {};
    try { payload = await response.json(); } catch (_e) { payload = {}; }
    if (response.status === 401) {
      window.location.href = "/login?reason=expired";
      throw new Error("Sesión expirada");
    }
    if (!response.ok) throw new Error(payload.error || "Error en la petición (" + response.status + ")");
    return payload;
  }

  function toast(message, type) {
    const region = document.querySelector(".toast-region");
    if (!region) return;
    const el = document.createElement("div");
    el.className = "toast " + (type || "");
    el.textContent = message;
    region.appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }

  function showError(form, message) {
    let box = form.querySelector(".form-error");
    if (!box) {
      box = document.createElement("div");
      box.className = "form-error";
      form.insertBefore(box, form.firstChild);
    }
    box.textContent = message;
  }

  function clearError(form) {
    const box = form.querySelector(".form-error");
    if (box) box.remove();
  }

  function initNavigation() {
    const toggle = document.querySelector(".menu-toggle");
    const sidebar = document.querySelector(".sidebar");
    if (toggle && sidebar) toggle.addEventListener("click", () => sidebar.classList.toggle("open"));
    const logout = document.querySelector("[data-logout]");
    if (logout) {
      logout.addEventListener("click", async () => {
        try { await api("/api/auth/logout", { method: "POST" }); } catch (_e) { /* noop */ }
        window.location.href = "/login";
      });
    }
  }

  function initLogin() {
    const form = document.getElementById("login-form");
    if (!form) return;
    document.querySelectorAll(".demo-user").forEach((chip) => {
      chip.addEventListener("click", () => {
        form.querySelector("[name=username]").value = chip.dataset.user || "";
        form.querySelector("[name=password]").value = chip.dataset.pass || "";
      });
    });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      clearError(form);
      const button = form.querySelector("button[type=submit]");
      button.disabled = true;
      try {
        const data = await api("/api/auth/login", {
          method: "POST",
          body: {
            username: form.querySelector("[name=username]").value,
            password: form.querySelector("[name=password]").value,
            next: form.dataset.next || "",
          },
        });
        window.location.href = data.redirect || "/app";
      } catch (err) {
        showError(form, err.message);
        button.disabled = false;
      }
    });
  }

  function initCourses() {
    const form = document.getElementById("course-form");
    if (form) {
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        clearError(form);
        const body = {};
        new FormData(form).forEach((value, key) => { body[key] = value; });
        try {
          await api("/api/cursos", { method: "POST", body: body });
          toast("Curso creado correctamente", "ok");
          setTimeout(() => window.location.reload(), 500);
        } catch (err) { showError(form, err.message); }
      });
    }
    document.querySelectorAll("[data-enroll]").forEach((button) => {
      button.addEventListener("click", async () => {
        try {
          await api("/api/cursos/" + button.dataset.enroll + "/inscribir", { method: "POST" });
          toast("Inscripción registrada", "ok");
          setTimeout(() => window.location.reload(), 500);
        } catch (err) { toast(err.message, "error"); }
      });
    });
  }

  function initGrades() {
    document.querySelectorAll("[data-grade]").forEach((input) => {
      input.addEventListener("change", async () => {
        try {
          await api("/api/inscripciones/" + input.dataset.grade + "/calificacion", {
            method: "POST", body: { grade: input.value },
          });
          toast("Calificación guardada", "ok");
        } catch (err) { toast(err.message, "error"); }
      });
    });
  }

  function initUsers() {
    const form = document.getElementById("user-form");
    if (!form) return;
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      clearError(form);
      const body = {};
      new FormData(form).forEach((value, key) => { body[key] = value; });
      try {
        await api("/api/usuarios", { method: "POST", body: body });
        toast("Usuario creado con acceso restringido", "ok");
        form.reset();
        setTimeout(() => window.location.reload(), 600);
      } catch (err) { showError(form, err.message); }
    });
  }

  function initStudentSearch() {
    const input = document.getElementById("student-search");
    const target = document.getElementById("student-results");
    if (!input || !target) return;
    let timer = null;
    input.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        try {
          const data = await api("/api/estudiantes?q=" + encodeURIComponent(input.value));
          target.innerHTML = "";
          data.estudiantes.forEach((student) => {
            const row = document.createElement("tr");
            [student.full_name, "@" + student.username, student.email].forEach((text) => {
              const cell = document.createElement("td");
              cell.textContent = text; // Never innerHTML con datos del servidor.
              row.appendChild(cell);
            });
            target.appendChild(row);
          });
        } catch (err) { toast(err.message, "error"); }
      }, 220);
    });
  }

  function initModals() {
    document.querySelectorAll("[data-modal-open]").forEach((button) => {
      button.addEventListener("click", () => {
        const modal = document.getElementById(button.dataset.modalOpen);
        if (modal) modal.classList.add("open");
      });
    });
    document.querySelectorAll("[data-modal-close]").forEach((button) => {
      button.addEventListener("click", () => button.closest(".modal-backdrop").classList.remove("open"));
    });
  }

  function initLab() {
    document.querySelectorAll("[data-copy]").forEach((button) => {
      button.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(button.dataset.copy);
          toast("Payload copiado", "ok");
        } catch (_e) { toast("No se pudo copiar", "error"); }
      });
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initLogin();
    initCourses();
    initGrades();
    initUsers();
    initStudentSearch();
    initModals();
    initLab();
  });
})();
