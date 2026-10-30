let currentMode = "inseguro";

function toggleMode() {
  currentMode = currentMode === "inseguro" ? "seguro" : "inseguro";
  const btn = document.getElementById("mode-btn");
  const label = document.getElementById("mode-label");

  if (currentMode === "seguro") {
    btn.className = "api-toggle protected";
    label.textContent = "API v2.0";
  } else {
    btn.className = "api-toggle";
    label.textContent = "API v1.0";
  }

  cargarDirectorio("");
}

function filtrarDirectorio(e) {
  e.preventDefault();
  const distinctOn = document.getElementById("inp-distinct").value.trim();
  cargarDirectorio(distinctOn);
}

async function cargarDirectorio(distinctOn) {
  const toast = document.getElementById("toast");
  toast.className = "toast";
  toast.textContent = "";

  const res = await fetch(`/api/${currentMode}/usuarios`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ distinctOn }),
  });

  const payload = await res.json();
  pintarTabla(res, payload);
}

async function guardarPerfil(e) {
  e.preventDefault();
  const raw = document.getElementById("inp-department").value.trim();
  const toast = document.getElementById("toast");
  toast.className = "toast";
  toast.textContent = "";

  let departmentValue = raw;
  if (raw.startsWith("{")) {
    try {
      departmentValue = JSON.parse(raw);
    } catch {
      toast.className = "toast error";
      toast.textContent = "Formato de entrada no válido.";
      return;
    }
  }

  const res = await fetch(`/api/${currentMode}/guardar`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: 1, department: departmentValue }),
  });

  const payload = await res.json();
  if (res.ok) {
    toast.className = "toast success";
    toast.textContent = "Perfil actualizado correctamente.";
  }
  pintarTabla(res, payload);
}

function pintarTabla(res, payload) {
  const toast = document.getElementById("toast");
  const tbody = document.getElementById("results-body");

  if (!res.ok) {
    toast.className = "toast error";
    toast.textContent = `HTTP ${res.status} — ${payload.error}`;
    return;
  }

  const users = payload.data || [];
  if (users.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:#64748b;">No hay registros para mostrar.</td></tr>`;
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
      </tr>
    `
    )
    .join("");
}

// Carga inicial
cargarDirectorio("");
