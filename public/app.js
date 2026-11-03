// Modo activo: "vulnerable" (API v1.0) o "seguro" (API v2.0).
let currentMode = "vulnerable";

function toggleMode() {
  currentMode = currentMode === "vulnerable" ? "seguro" : "vulnerable";

  const btn = document.getElementById("mode-btn");
  const label = document.getElementById("mode-label");
  const banner = document.getElementById("mode-banner");
  const bannerText = document.getElementById("mode-banner-text");

  if (currentMode === "seguro") {
    btn.className = "api-toggle protected";
    label.textContent = "API v2.0";
    banner.className = "mode-banner-inner protected";
    bannerText.innerHTML =
      "<strong>API v2.0 (protegida):</strong> Zod valida los tipos y una lista blanca " +
      "restringe las columnas antes de llegar a TypeORM. Los ataques devuelven 400.";
  } else {
    btn.className = "api-toggle";
    label.textContent = "API v1.0";
    banner.className = "mode-banner-inner vulnerable";
    bannerText.innerHTML =
      "<strong>API v1.0 (vulnerable):</strong> la entrada del usuario llega a TypeORM " +
      "sin validar. Los dos ataques funcionan.";
  }

  cargarDirectorio("");
}

function filtrarDirectorio(e) {
  e.preventDefault();
  const distinctOn = document.getElementById("inp-distinct").value.trim();
  cargarDirectorio(distinctOn);
}

async function cargarDirectorio(distinctOn) {
  resetToast();
  const res = await fetch(`/api/${currentMode}/directorio`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ distinctOn }),
  });
  pintarTabla(res, await res.json());
}

async function guardarPerfil(e) {
  e.preventDefault();
  resetToast();

  const raw = document.getElementById("inp-department").value.trim();

  // Si el usuario escribe un objeto JSON (empieza por "{"), lo enviamos como
  // objeto anidado -> así se dispara el intento de CVE-2025-60542.
  let departmentValue = raw;
  if (raw.startsWith("{")) {
    try {
      departmentValue = JSON.parse(raw);
    } catch {
      return mostrarToast("error", "Formato de entrada no válido (JSON mal formado).");
    }
  }

  // API vulnerable: confía en el `id` del cuerpo (demostrable para IDOR).
  // API segura: NO enviamos `id`; el servidor usa el de la sesión autenticada.
  const body =
    currentMode === "vulnerable"
      ? { id: 1, department: departmentValue }
      : { department: departmentValue };

  const res = await fetch(`/api/${currentMode}/perfil`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  const payload = await res.json();
  if (res.ok) mostrarToast("success", "Perfil actualizado correctamente.");
  pintarTabla(res, payload);
}

function resetToast() {
  const toast = document.getElementById("toast");
  toast.className = "toast";
  toast.textContent = "";
}

function mostrarToast(tipo, texto) {
  const toast = document.getElementById("toast");
  toast.className = `toast ${tipo}`;
  toast.textContent = texto;
}

function pintarTabla(res, payload) {
  if (!res.ok) {
    return mostrarToast("error", `HTTP ${res.status} — ${payload.error}`);
  }

  const users = payload.data || [];
  const tbody = document.getElementById("results-body");

  if (users.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="6" style="text-align:center;color:#64748b;">No hay registros para mostrar.</td></tr>';
    return;
  }

  tbody.innerHTML = users
    .map(
      (u) => `
      <tr class="${u.role === "admin" ? "admin-row" : ""}">
        <td>#${u.id}</td>
        <td><strong>@${u.username}</strong></td>
        <td>${u.fullName}</td>
        <td><span class="badge badge-${u.role}">${u.role}</span></td>
        <td>${u.department}</td>
        <td>${u.email || '<span style="color:#94a3b8;">Privado</span>'}</td>
      </tr>`
    )
    .join("");
}

// Carga inicial del directorio.
cargarDirectorio("");
