import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Card, Empty, fmtDate } from "../components/ui.jsx";

function ChangePassword() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [msg, setMsg] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setMsg(null);
    try {
      await api.changePassword(current, next);
      setMsg({ ok: true, text: "Senha alterada. As outras sessões abertas foram encerradas." });
      setCurrent("");
      setNext("");
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    }
  };

  return (
    <Card title="Alterar minha senha" sub="Mínimo de 10 caracteres, sem conter o nome de usuário.">
      <form onSubmit={submit}>
        <label className="field">
          <span>Senha atual</span>
          <input type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} />
        </label>
        <label className="field">
          <span>Nova senha</span>
          <input type="password" autoComplete="new-password" required minLength={10} value={next} onChange={(e) => setNext(e.target.value)} />
        </label>
        {msg && <p className={msg.ok ? "secondary" : "error"}>{msg.text}</p>}
        <button className="btn primary">Alterar senha</button>
      </form>
    </Card>
  );
}

export default function Users({ user }) {
  const [users, setUsers] = useState(null);
  const [form, setForm] = useState({ username: "", password: "", role: "analyst" });
  const [error, setError] = useState(null);
  const isAdmin = user.role === "admin";

  const load = () => isAdmin && api.users().then(setUsers).catch((e) => setError(e.message));
  useEffect(() => {
    load();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const create = async (e) => {
    e.preventDefault();
    setError(null);
    try {
      await api.createUser(form);
      setForm({ username: "", password: "", role: "analyst" });
      load();
    } catch (err) {
      setError(err.message);
    }
  };

  const remove = async (u) => {
    if (!window.confirm(`Remover o usuário "${u.username}"? As sessões dele serão encerradas.`)) return;
    try {
      await api.deleteUser(u.id);
      load();
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{isAdmin ? "Usuários e acesso" : "Minha conta"}</h1>
          <p>Conectado como <b>{user.username}</b> ({user.role === "admin" ? "administrador" : "analista"}).</p>
        </div>
      </div>
      <div className={isAdmin ? "grid two" : "grid half"}>
        {isAdmin && (
          <Card title="Usuários" sub="Analistas fazem scans e triagem; administradores também gerenciam usuários.">
            {!users ? (
              <Empty>Carregando...</Empty>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table>
                  <thead>
                    <tr><th>Usuário</th><th>Perfil</th><th>Último acesso</th><th /></tr>
                  </thead>
                  <tbody>
                    {users.map((u) => (
                      <tr key={u.id}>
                        <td><b>{u.username}</b></td>
                        <td><span className="badge">{u.role === "admin" ? "administrador" : "analista"}</span></td>
                        <td className="secondary">{u.last_login_at ? fmtDate(u.last_login_at) : "nunca"}</td>
                        <td className="num">
                          {u.id !== user.id && <button className="btn" onClick={() => remove(u)}>Remover</button>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <h2 style={{ marginTop: 20 }}>Novo usuário</h2>
            <form onSubmit={create} className="toolbar" style={{ marginTop: 8 }}>
              <input type="text" placeholder="usuário" required pattern="[A-Za-z0-9._\-]{3,80}" value={form.username}
                     onChange={(e) => setForm({ ...form, username: e.target.value })} />
              <input type="password" placeholder="senha (mín. 10)" required minLength={10} autoComplete="new-password"
                     value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
              <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
                <option value="analyst">analista</option>
                <option value="admin">administrador</option>
              </select>
              <button className="btn primary">Criar</button>
            </form>
            {error && <p className="error">{error}</p>}
          </Card>
        )}
        <ChangePassword />
      </div>
    </>
  );
}
