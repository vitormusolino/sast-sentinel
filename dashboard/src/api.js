const BASE = import.meta.env.VITE_API_BASE || "";

// avisa o App quando a sessão expira/é revogada, para voltar à tela de login
export const UNAUTHORIZED_EVENT = "sast:unauthorized";

async function request(path, options = {}) {
  // o cookie de sessão (HttpOnly) vai automaticamente; o JavaScript nunca vê o token
  const resp = await fetch(`${BASE}${path}`, { credentials: "same-origin", ...options });
  if (!resp.ok) {
    if (resp.status === 401 && !path.startsWith("/api/auth/")) {
      window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    }
    let detail = resp.statusText;
    try {
      const body = await resp.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* corpo nao-JSON */
    }
    const error = new Error(detail);
    error.status = resp.status;
    throw error;
  }
  return resp.status === 204 ? null : resp.json();
}

const json = (method, body) => ({
  method,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

const qs = (params) => {
  const clean = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "" && v !== false);
  return clean.length ? "?" + new URLSearchParams(clean).toString() : "";
};

export const api = {
  // autenticação
  me: () => request("/api/auth/me"),
  login: (username, password) => request("/api/auth/login", json("POST", { username, password })),
  logout: () => request("/api/auth/logout", { method: "POST" }),
  changePassword: (current_password, new_password) =>
    request("/api/auth/password", json("POST", { current_password, new_password })),
  users: () => request("/api/users"),
  createUser: (payload) => request("/api/users", json("POST", payload)),
  deleteUser: (id) => request(`/api/users/${id}`, { method: "DELETE" }),

  // plataforma
  health: () => request("/api/health"),
  projects: () => request("/api/projects"),
  overview: (projectId) => request(`/api/metrics/overview${qs({ project_id: projectId })}`),
  scans: (projectId) => request(`/api/scans${qs({ project_id: projectId })}`),
  scan: (id) => request(`/api/scans/${id}`),
  findings: (id, filters) => request(`/api/scans/${id}/findings${qs(filters)}`),
  finding: (id) => request(`/api/findings/${id}`),
  triage: (id, status, reason) => request(`/api/findings/${id}`, json("PATCH", { status, reason })),
  rules: () => request("/api/rules"),
  scanGit: (payload) => request("/api/scans/git", json("POST", payload)),
  scanUpload: (form) => request("/api/scans/upload", { method: "POST", body: form }),
  sarifUrl: (id) => `${BASE}/api/scans/${id}/sarif`,
  reportUrl: (id) => `${BASE}/api/scans/${id}/report.pdf`,
};
