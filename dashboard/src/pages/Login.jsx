import { useState } from "react";
import { api } from "../api.js";

export default function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onLogin(await api.login(username, password));
    } catch (err) {
      setError(err.message);
      setPassword("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-page">
      <form className="card login-card" onSubmit={submit}>
        <div className="brand login-brand">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path fill="var(--accent)" d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5z" />
            <path fill="var(--surface-1)" d="m10.5 15.5-3-3 1.4-1.4 1.6 1.6 4.6-4.6 1.4 1.4z" />
          </svg>
          SAST Sentinel
        </div>
        <p className="secondary login-sub">Plataforma de análise estática de segurança</p>
        <label className="field">
          <span>Usuário</span>
          <input type="text" autoComplete="username" autoFocus required value={username}
                 onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label className="field">
          <span>Senha</span>
          <input type="password" autoComplete="current-password" required value={password}
                 onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && <p className="error" role="alert">{error}</p>}
        <button className="btn primary" style={{ width: "100%" }} disabled={busy}>
          {busy ? "Entrando..." : "Entrar"}
        </button>
        <p className="muted login-foot">Sessão protegida por cookie HttpOnly · bloqueio após tentativas inválidas</p>
      </form>
    </div>
  );
}
