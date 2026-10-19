# Roteiro da apresentação (≈ 2 min) + demonstração

Slides: deck "SAST Sentinel - Apresentação" (7 slides). A fala de cada slide também está nas notas do apresentador.
Sugestão: um integrante por bloco; ensaiem com cronômetro.

## Fala (≈ 2 min, cerca de 280 palavras)

| # | Slide | Quem | Tempo | Fala |
|---|---|---|---|---|
| 1 | Capa | Apresentador 1 | 15 s | Boa noite, professor. Nós somos o grupo do SAST Sentinel: uma plataforma que analisa código-fonte sem executá-lo, encontra vulnerabilidades e impede que código inseguro entre no projeto. Em dois minutos mostramos o que construímos e depois vamos direto para a plataforma rodando. |
| 2 | O problema | Apresentador 1 | 15 s | Uma falha encontrada em produção custa muito mais caro do que no momento em que o código é escrito. A nossa resposta junta três ideias: SAST, que analisa sem executar; shift-left, que leva a segurança para cada commit; e o Security Gate, que bloqueia o Pull Request inseguro antes do merge. |
| 3 | Arquitetura | Apresentador 2 | 20 s | A arquitetura é containerizada. O código entra pelo dashboard, por upload ou repositório Git, ou pelo GitHub Actions em cada PR. A API em FastAPI registra o pedido e coloca na fila do Redis; workers Celery fazem o trabalho pesado e escalam. O motor roda cinco analisadores e consulta um LLM local no Ollama, então o código nunca sai da máquina. Os resultados ficam no Postgres e viram SARIF para o GitHub. |
| 4 | Motor SAST | Apresentador 3 | 20 s | O coração é o motor. Além de regras, ele faz taint analysis: segue o dado do usuário até a função perigosa, inclusive entre arquivos. No benchmark com gabarito: 96,2% de precisão e 100% de recall em 50 vulnerabilidades, contra 44% do Bandit sozinho. Python, Java e JavaScript são nativos; outras 10 linguagens via Semgrep. |
| 5 | IA | Apresentador 4 | 20 s | A IA roda localmente. Ela explica a falha, o cenário de exploração e sugere a correção, e o próprio motor reanalisa o patch: só ganha o selo se a vulnerabilidade some. Medimos com honestidade: modelos locais pequenos não removem os falsos positivos difíceis e chegam a errar com confiança total. Por isso a IA ajuda, mas não decide. |
| 6 | DevSecOps | Apresentador 5 | 20 s | Todo Pull Request passa pelo GitHub Actions: nosso SAST, Gitleaks para segredos e auditoria de dependências. Achado HIGH ou CRITICAL: merge bloqueado e relatório comentado no PR. E a plataforma se protege: login com boas práticas, perfis de acesso, e o gate analisa o nosso próprio código. |
| 7 | Demonstração | Apresentador 5 | 10 s | Resumindo: análise estática com taint, IA que corrige e se deixa verificar, e um gate que bloqueia código inseguro. Agora vamos mostrar funcionando. |

## Demonstração (≈ 5 min)

**Antes da apresentação (no dia):**
- Docker Desktop aberto, `docker compose up -d`, http://localhost:8080 respondendo.
- Scan com IA do `samples/vulnerable_app` já executado uma vez (fica em cache).
- Uma aba aberta no PR de demonstração: https://github.com/vitormusolino/sast-sentinel/pull/1
- Um terminal na pasta do projeto.

| Passo | O que fazer | O que destacar |
|---|---|---|
| 1. Login | Abrir http://localhost:8080 e entrar com `admin` | Senha com scrypt, cookie HttpOnly, bloqueio após 5 tentativas (se quiser, erre a senha uma vez) |
| 2. Dashboard | Visão executiva | KPIs, tendência caindo (o time corrigindo), severidade, top 5 arquivos críticos, CWEs |
| 3. Scan | *Varreduras → Upload .zip* do `vulnerable_app` com IA marcada (já em cache, termina em segundos) | Abrir um CRITICAL de SQL Injection: o caminho do taint passando de `app.py` para `db.py` |
| 4. IA | No mesmo achado: "Análise da IA" e "Código corrigido sugerido" | Selo **✓ verificado pelo motor**; guardrails (a IA não apaga achados) |
| 5. Triagem | Marcar um achado como falso positivo | A decisão vale para os próximos scans (fingerprint estável) |
| 6. Terminal (opcional) | No **PowerShell**: `docker compose exec api sast scan /opt/samples/vulnerable_app` (no Git Bash, prefixe com `MSYS_NO_PATHCONV=1`, senão o caminho é convertido) | O mesmo motor na CLI, o código de saída 1 é o que bloqueia o pipeline |
| 7. GitHub | PR #1 | Gate vermelho, comentário "⛔ BLOQUEADO", alerta do Code Scanning na linha, botão de merge bloqueado |

**Plano B:** se o Docker ou o Ollama falharem, mostrem o PR #1 no GitHub e as Actions verdes da `main`. Tudo isso funciona sem o notebook.

Perguntas prováveis e respostas: [DEFESA.md](DEFESA.md).
