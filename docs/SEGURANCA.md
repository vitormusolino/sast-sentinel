# Segurança da própria plataforma

Uma ferramenta que guarda **as vulnerabilidades do código de outras pessoas** é um alvo valioso. Este documento descreve como o SAST Sentinel se protege, mapeado ao OWASP Top 10.

## Autenticação e sessões (A07 - Identification and Authentication Failures)

| Controle | Implementação | Por quê |
|---|---|---|
| Hash de senha | **scrypt** (N=2¹⁴, r=8, p=1) com salt aleatório de 128 bits por usuário, comparação em tempo constante | scrypt exige muita memória, o que encarece ataques com GPU/ASIC; o salt impede tabelas pré-computadas |
| Política de senha | mínimo de 10 caracteres e não pode conter o nome de usuário | evita as senhas triviais mais comuns |
| Token de sessão | 256 bits de `secrets.token_urlsafe`; **no banco fica só o SHA-256** | se o banco vazar, as sessões não podem ser reaproveitadas |
| Cookie | `HttpOnly` + `SameSite=Strict` + `Secure` (configurável para HTTPS) | o JavaScript não lê o token (mitiga XSS) e o navegador não envia em requisições de outros sites (mitiga CSRF) |
| Expiração | 8 h (`SESSION_HOURS`); logout **revoga** a sessão no servidor | um token copiado deixa de valer após o logout |
| Força bruta | bloqueio de 5 min após 5 falhas por usuário+IP (resposta `429`) | limita a adivinhação de senha online |
| Enumeração de usuários | mesma mensagem ("usuário ou senha inválidos") e **mesmo tempo de resposta** para usuário inexistente (hash fictício) | o atacante não descobre quais usuários existem |
| Sem senha padrão | admin criado de `ADMIN_PASSWORD`; se vazio, senha **aleatória** exibida uma única vez no log | evita o clássico `admin/admin` |
| Troca de senha | exige a senha atual e **encerra as outras sessões** | um login esquecido em outra máquina deixa de valer |
| Auditoria | logins (ok/falha/bloqueio), criação/remoção de usuários e trocas de senha em log `sast.audit` | rastreabilidade |

## Autorização (A01 - Broken Access Control)

- **Tudo exige login**, exceto `/api/auth/login` e `/api/health` (healthcheck do Docker). Testado: as rotas devolvem `401` sem sessão.
- **Perfis**: *analista* faz scans e triagem; *administrador* também gerencia usuários (`403` para analistas).
- **Ingestão do CI** (`/api/scans/import`) usa uma credencial **de máquina** (`X-API-Key`), separada das sessões de usuários.
- O admin não pode remover a própria conta (evita ficar sem administrador).

## Entrada de código não confiável

| Ameaça | Mitigação |
|---|---|
| Zip Slip / zip bomb | rejeita caminhos absolutos e `..`, ignora symlinks, limita o número de arquivos e o tamanho descompactado |
| SSRF / injeção de argumentos via URL git | apenas `https://`, allowlist de hosts, sem credenciais na URL, `--` antes da URL, branch validada |
| Execução do código analisado | o motor **só faz parsing**, nunca executa |
| Path traversal ao servir o dashboard | allowlist fechada com os arquivos do build (a URL nunca vira caminho de disco) |

## Infraestrutura e cadeia de suprimentos

- Contêineres com **usuário sem privilégios** (uid 10001), imagens slim.
- nginx com **CSP** restritiva, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`.
- **pip-audit**, **npm audit** e **Gitleaks** em todo PR; versões fixadas sem CVEs conhecidas.
- **LLM local** (Ollama): o código analisado não sai da máquina.
- **Dogfooding**: o SAST Sentinel analisa o próprio código em todo PR. Ele já bloqueou um SHA-1 nosso e revelou um falso positivo na própria regra de segredos.

## Limitações conhecidas
- O bloqueio de força bruta é em memória: suficiente para uma instância da API; com várias réplicas, deveria ir para o Redis.
- Não há MFA nem SSO (OIDC). Seriam os próximos passos em um ambiente corporativo.
- Sem HTTPS no `docker compose` local; em produção, use um proxy TLS e `COOKIE_SECURE=true`.
