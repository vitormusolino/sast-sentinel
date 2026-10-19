# Roteiro da defesa técnica

Tempo sugerido: **15 min de apresentação + 5 min de perguntas**. Cada integrante apresenta a parte que construiu.

## Estrutura (alinhada aos critérios de avaliação)

| Min | Bloco | Critério (peso) | Quem | Mensagem-chave |
|---|---|---|---|---|
| 0–1 | Problema e shift-left | — | P1 | Corrigir em produção custa caro; o SAST no PR pega o problema no commit |
| 1–4 | **Arquitetura** | Arquitetura (25 %) | P2 | C4, microsserviços, fila assíncrona, LLM local, segurança da própria plataforma |
| 4–8 | **Motor SAST + demo** | Robustez SAST (30 %) | P3 | Aliases de import, taint interprocedural entre arquivos, sanitizadores por categoria, **benchmark 94,9 %** |
| 8–11 | **IA + demo** | Inovação IA (20 %) | P4 | Guardrails + **remediação auto-verificada** pelo motor |
| 11–13 | **DevSecOps + demo** | DevSecOps (15 %) | P5 | PR bloqueado ao vivo, SARIF no GitHub, baseline, dogfooding |
| 13–15 | Análise crítica e próximos passos | Defesa (10 %) | P1 | FPs/FNs reais, viés do corpus, roadmap |

## Roteiro de demonstração (ensaie!)

**Antes:** `docker compose up -d`, modelo já baixado, seed rodado, **e o scan com IA do `vulnerable_app` executado uma vez** (em CPU leva ~11 min para 10 achados; as respostas ficam em cache e, na apresentação, o mesmo scan termina em ~5 s), um PR vulnerável preparado no GitHub, e o navegador aberto no dashboard.

1. **Dashboard (1 min):** mostre a visão executiva: KPIs, tendência caindo (o time corrigindo), top 5 arquivos críticos, CWEs.
2. **CLI no terminal (2 min):**
   ```bash
   sast scan samples/vulnerable_app -v
   ```
   Destaque o achado `app.py:39`, cujo caminho de taint **atravessa para `db.py`**. Depois mostre que o `safe_app` (mesmos cenários corrigidos) sai **limpo**:
   ```bash
   sast scan samples/safe_app
   ```
3. **Benchmark (30 s):** `sast benchmark samples` mostra a tabela vs. Bandit.
4. **IA (2 min):** no dashboard, *Nova varredura → upload de `samples/vulnerable_app` (zip) com IA ligada*. Abra um CRITICAL e mostre a explicação, o cenário de exploração, o código corrigido e o selo **✓ verificado pelo motor**. Explique os guardrails.
5. **Pipeline (2 min):** mostre o PR de demonstração [vitormusolino/sast-sentinel#1](https://github.com/vitormusolino/sast-sentinel/pull/1), já aberto e bloqueado. Se quiser fazer ao vivo: abra o PR que adiciona `os.system("ping " + request.args["h"])`. Mostre o job vermelho, o **comentário automático no PR**, o alerta inline (Code Scanning) e o merge bloqueado. Depois mostre o commit de correção deixando o check verde.

**Plano B:** se o Ollama estiver lento, use o modo heurístico (o dashboard mostra "modo heurístico") e mostre os testes com LLM *fake* que provam os guardrails. Grave um vídeo da demo como backup.

## Perguntas prováveis (e respostas)

**Por que não usar só Semgrep/Bandit?**
Eles fazem *pattern matching* local. O Bandit não rastreia o dado entre funções nem entre arquivos, e no nosso corpus achou 56 % das vulnerabilidades contra 95 % do nosso motor. Usamos os dois como segunda opinião (consenso), não como motor principal.

**Como vocês reduzem falsos positivos?**
Em 5 camadas: (1) filtros de contexto nas regras (literal constante, placeholders, nomes como `*_field`); (2) taint, que só reporta quando há fluxo real de dado externo; (3) sanitizadores por categoria e guardas de allowlist; (4) consenso entre motores; (5) triagem por LLM com guardrails. Mais a triagem humana persistente por fingerprint.

**E se o LLM alucinar?**
Ele não tem poder de veto: muda a severidade em no máximo ±1, só sugere FP com alta confiança e o achado nunca é apagado. E o código que ele sugere é **verificado pelo motor**: se não compila ou se a vulnerabilidade continua, o patch é marcado como não verificado.

**A IA realmente reduz falsos positivos?**
Medimos (`sast benchmark --ai`): com modelos locais de 3B e 7B, **não**. Eles não descartaram nenhum dos 2 falsos positivos difíceis, mas também não descartaram nenhuma vulnerabilidade real. O qwen chegou a errar com confiança 1,0, e é exatamente por isso que a IA não tem poder de veto. O ganho concreto está nas explicações e nas correções verificadas pelo motor (2 de 6 com o qwen). Mostrar isso é análise crítica: preferimos medir a prometer.

**Por que LLM local e não o GPT/Claude?**
Confidencialidade e propriedade intelectual do código analisado (o próprio enunciado exige isso), custo zero por chamada e funcionamento offline. O trade-off é a qualidade menor de modelos pequenos, compensada pelos guardrails e pela verificação.

**Como escala?**
A API é stateless e os workers Celery escalam horizontalmente (`--scale worker=N`); `acks_late` e `prefetch=1` evitam perder ou prender tarefas. O gargalo é o LLM, mitigado com prioridade por severidade, limite de achados por scan e cache por hash.

**Como o gate não trava um projeto legado?**
Com o baseline: só achados **novos** bloqueiam. O fingerprint não depende da linha, então código que só "mudou de lugar" não vira achado novo.

**Qual o maior limite do motor hoje?**
Despacho dinâmico (`getattr`), shell implícito via `sh -c` e validação semântica (`urlparse`). Estão no corpus e aparecem como FN/FP no benchmark. Preferimos medir e mostrar do que esconder.

**O que é o fingerprint e por que não usar arquivo:linha?**
`sha1(regra + arquivo + trecho normalizado)`. Se alguém adiciona 10 linhas acima, `arquivo:linha` mudaria e o achado pareceria "novo" e "corrigido" ao mesmo tempo. O fingerprint é estável.

**Tem controle de acesso?**
Sim: login com scrypt, sessão em cookie `HttpOnly`/`SameSite=Strict` (só o hash do token no banco), bloqueio de força bruta, mensagem idêntica para usuário inexistente, sem senha padrão e perfis admin/analista. O CI entra com uma chave de máquina separada. Detalhes em `docs/SEGURANCA.md`.

**Como garantem que a própria plataforma é segura?**
Ela passa pelo próprio gate (dogfooding: já pegou um SHA-1 nosso), tem proteção contra Zip Slip e zip bomb, allowlist de hosts git (anti-SSRF), roda com usuário sem privilégios, usa CSP no nginx e API key na ingestão, e não executa o código analisado.

**Ética?**
O corpus foi escrito pelo grupo, com segredos falsos. A plataforma só clona via HTTPS de hosts permitidos, e a orientação é usar apenas em código próprio ou open source com licença compatível.

## Checklist final de entrega
- [ ] README com nomes/RM da equipe preenchidos
- [ ] Repositório no GitHub com Actions verdes na `main` e um PR de demonstração bloqueado
- [ ] Branch protection ativada (print na apresentação)
- [ ] `docker compose up` testado do zero em outra máquina
- [ ] Modelo do Ollama baixado antes da apresentação
- [ ] Benchmark atualizado (`docs/benchmark-resultado.md`)
- [ ] Slides com diagramas C4 (copiar de `docs/ARQUITETURA.md`) e a tabela do benchmark
- [ ] Vídeo de backup da demonstração
