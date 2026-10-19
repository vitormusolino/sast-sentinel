import { useEffect, useState } from "react";
import { UNAUTHORIZED_EVENT, api } from "./api.js";
import Login from "./pages/Login.jsx";
import Overview from "./pages/Overview.jsx";
import Rules from "./pages/Rules.jsx";
import ScanDetail from "./pages/ScanDetail.jsx";
import Scans from "./pages/Scans.jsx";
import Users from "./pages/Users.jsx";

function useHashRoute() {
  const parse = () => {
    const raw = window.location.hash.replace(/^#/, "") || "/";
    const [path, search = ""] = raw.split("?");
    return { path, query: new URLSearchParams(search) };
  };
  const [route, setRoute] = useState(parse);
  useEffect(() => {
    const onChange = () => setRoute(parse());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

const navigate = (path) => {
  window.location.hash = path;
};

function readTheme() {
  try {
    return localStorage.getItem("theme") || "auto";
  } catch {
    return "auto";
  }
}

export default function App() {
  const { path, query } = useHashRoute();
  // undefined = verificando sessão · null = não logado · objeto = usuário logado
  const [user, setUser] = useState(undefined);
  const [projects, setProjects] = useState([]);
  const [projectId, setProjectId] = useState("");
  const [health, setHealth] = useState(null);
  const [theme, setTheme] = useState(readTheme);

  useEffect(() => {
    api.me().then(setUser).catch(() => setUser(null));
    const onUnauthorized = () => setUser(null);
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  useEffect(() => {
    if (!user) return;
    api.projects().then(setProjects).catch(() => {});
    api.health().then(setHealth).catch(() => setHealth({ status: "down" }));
  }, [path, user]);

  useEffect(() => {
    if (theme === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("theme", theme);
    } catch {
      /* armazenamento indisponível */
    }
  }, [theme]);

  const logout = async () => {
    try {
      await api.logout();
    } finally {
      setUser(null);
      setProjects([]);
      navigate("/");
    }
  };

  if (user === undefined) return null; // evita "piscar" a tela de login enquanto verifica a sessão
  if (user === null) return <Login onLogin={setUser} />;

  const scanMatch = path.match(/^\/scans\/(\d+)/);
  let page;
  if (scanMatch) page = <ScanDetail scanId={scanMatch[1]} query={query} navigate={navigate} />;
  else if (path.startsWith("/scans")) page = <Scans projectId={projectId} navigate={navigate} />;
  else if (path.startsWith("/rules")) page = <Rules />;
  else if (path.startsWith("/users")) page = <Users user={user} />;
  else page = <Overview projectId={projectId} navigate={navigate} />;

  const link = (to, label) => {
    const active = to === "/" ? path === "/" : path.startsWith(to);
    return <a href={`#${to}`} className={active ? "active" : ""}>{label}</a>;
  };

  const dot = (ok) => <i className="dot" style={{ background: ok ? "var(--good)" : "var(--sev-info)" }} />;

  return (
    <>
      <header className="topbar">
        <div className="brand">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path fill="var(--accent)" d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5z" /><path fill="var(--surface-1)" d="m10.5 15.5-3-3 1.4-1.4 1.6 1.6 4.6-4.6 1.4 1.4z" /></svg>
          SAST Sentinel
        </div>
        <nav className="nav">
          {link("/", "Dashboard")}
          {link("/scans", "Varreduras")}
          {link("/rules", "Regras")}
          {link("/users", user.role === "admin" ? "Usuários" : "Conta")}
        </nav>
        <div className="spacer" />
        {health && (
          <div className="health" title={health.llm?.url}>
            <span>{dot(health.database)}API</span>
            <span>{dot(health.llm?.available)}LLM {health.llm?.model}</span>
            <span>{dot(health.tools?.semgrep)}Semgrep</span>
          </div>
        )}
        <select value={projectId} onChange={(e) => setProjectId(e.target.value)} aria-label="Projeto">
          <option value="">Todos os projetos</option>
          {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <select value={theme} onChange={(e) => setTheme(e.target.value)} aria-label="Tema">
          <option value="auto">Tema: sistema</option>
          <option value="light">Claro</option>
          <option value="dark">Escuro</option>
        </select>
        <div className="user-menu">
          <span className="secondary" title={user.role === "admin" ? "administrador" : "analista"}>{user.username}</span>
          <button className="btn" onClick={logout}>Sair</button>
        </div>
      </header>
      <main>{page}</main>
    </>
  );
}
