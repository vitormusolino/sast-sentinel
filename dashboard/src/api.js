const BASE = import.meta.env.VITE_API_BASE || "";

async function request(path, options = {}) {
  const resp = await fetch(`${BASE}${path}`, options);
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const body = await resp.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* corpo nao-JSON */
    }
    throw new Error(detail);
  }
  return resp.status === 204 ? null : resp.json();
}

const qs = (params) => {
  const clean = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "" && v !== false);
  return clean.length ? "?" + new URLSearchParams(clean).toString() : "";
};

export const api = {
  health: () => request("/api/health"),
  projects: () => request("/api/projects"),
  overview: (projectId) => request(`/api/metrics/overview${qs({ project_id: projectId })}`),
  scans: (projectId) => request(`/api/scans${qs({ project_id: projectId })}`),
  scan: (id) => request(`/api/scans/${id}`),
  findings: (id, filters) => request(`/api/scans/${id}/findings${qs(filters)}`),
  finding: (id) => request(`/api/findings/${id}`),
  triage: (id, status, reason) =>
    request(`/api/findings/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, reason }),
    }),
  rules: () => request("/api/rules"),
  scanGit: (payload) =>
    request("/api/scans/git", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  scanUpload: (form) => request("/api/scans/upload", { method: "POST", body: form }),
  sarifUrl: (id) => `${BASE}/api/scans/${id}/sarif`,
};
