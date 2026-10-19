# Benchmark de precisão e análise crítica

> Reproduza com: `sast benchmark samples -o docs/benchmark-resultado.md` (também roda no CI a cada push).
> Resultado bruto mais recente: [benchmark-resultado.md](benchmark-resultado.md).

## Metodologia
- **Gabarito**: cada linha vulnerável do corpus tem um comentário `# EXPECT: CWE-xx`. Um achado conta como **TP** se `(arquivo, linha, CWE)` bate com o gabarito; qualquer outro achado é **FP**; linha anotada sem achado é **FN**.
- **Corpus** (50 vulnerabilidades em Python, Java e JavaScript, código escrito pelo grupo):
  - `vulnerable_app/`: app Flask + Node com 34 vulnerabilidades clássicas, inclusive fluxos **entre arquivos**;
  - `safe_app/`: os mesmos cenários **implementados corretamente** (consulta parametrizada, `subprocess` com lista, `escape`, `secure_filename`, `secrets`...). Qualquer achado aqui é FP;
  - `java_app/`: controller Spring/Servlet com 11 vulnerabilidades (SQLi, command injection, path traversal, XSS, open redirect, desserialização, hash/cifra fracos, XXE, random inseguro, segredo);
  - `hard_cases/`: casos difíceis e **limitações conhecidas** (sanitizador da categoria errada, allowlists, `getattr`, `sh -c`, validação por `urlparse`).
- Comparação com o **Bandit** sozinho (com e sem nossa normalização de CWE) e com o modo de **consenso**.

## Resultados

| Ferramenta | TP | FP | FN | Precisão | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| **SAST Sentinel (AST + taint)** | 50 | 2 | 0 | **96,2 %** | **100 %** | **0,98** |
| Bandit (sozinho, CWE normalizado) | 22 | 4 | 28 | 84,6 % | 44,0 % | 0,58 |
| SAST Sentinel + Bandit (consenso) | 48 | 4 | 2 | 92,3 % | 96,0 % | 0,94 |

Por linguagem: **Java 11/11 detectadas, 0 FP** (`java_app` + `SafeController.java`); Python 34+ casos; JS 5. O Bandit só analisa Python, por isso o recall dele cai no corpus multilinguagem.

## Análise crítica

**1. O recall vem do taint.** O Bandit encontra padrões perigosos (*"usou `os.popen`"*), mas não sabe *de onde vem o dado*. Ele perde as rotas que passam o input para funções de outro arquivo (`find_user_by_name`, `run_backup`), XSS via `return f"<p>{x}</p>"`, SSRF, Open Redirect e Path Traversal, que só existem como **fluxo**, não como chamada isolada.

**2. Por que adicionar o Bandit piora a precisão?** No consenso, os achados *exclusivos* do Bandit entram como FPs (ex.: B608 na linha de montagem da query, B104 em comparações com `"0.0.0.0"`). Por isso o Bandit é **opcional** e usado como *segunda opinião*: quando ele concorda com o nosso motor, a confiança sobe; quando discorda sozinho, o achado entra com a confiança original e pode ser filtrado pelo gate (`min_confidence`).

**3. Os falsos positivos são casos de validação semântica:**
- `hard_cases/views.py:104` (CWE-601): `if urlparse(target).netloc: target = "/"` é uma validação que o motor não modela. Um LLM entende isso, e é aqui que a triagem por IA atua.
- `hard_cases/views.py:64` (CWE-89): SQL com f-string sobre `order_id`, que **é** inteiro (o taint sabe e não reporta), mas a regra de padrão PY006 dispara. É discutível: a recomendação de usar placeholder continua válida.

**4. Os falsos negativos foram eliminados** — eram `getattr(os, "system")(cmd)` (despacho dinâmico) e `subprocess.run(["sh", "-c", script])` (shell implícito). O motor passou a resolver `getattr` com nome constante e listas `sh/bash/cmd -c`. Continuam fora do alcance (e documentados em [MOTOR_SAST.md §5](MOTOR_SAST.md)) o `getattr` com nome calculado em tempo de execução e aliasing complexo — **recall 100 % no corpus não significa 100 % no mundo real**.

**5. Ameaças à validade (honestidade científica):**
- O corpus foi escrito pelo mesmo grupo que escreveu o motor, o que gera **viés de construção**. Mitigamos com `hard_cases/` (feito para quebrar o motor) e `safe_app/` (feito para gerar FPs), mas o número real em código de terceiros tende a ser menor.
- O corpus é pequeno (50 vulnerabilidades). Próximos passos: rodar contra benchmarks públicos como o **OWASP Benchmark** (Java) e projetos propositalmente vulneráveis com licença aberta (ex.: *DVPWA*, *PyGoat*), respeitando as licenças.
- A precisão da **IA** não está neste número: o benchmark do CI roda sem LLM, para ser determinístico. A medição com LLM (`--ai`) está em [IA.md](IA.md#resultado-medido-a-ia-reduz-falsos-positivos): os modelos locais (3B e 7B) **não** eliminaram os 2 FPs, mas também não descartaram nenhuma vulnerabilidade real.

## Evolução durante o desenvolvimento
| Mudança | Efeito medido |
|---|---|
| Normalizar CWE do Bandit + filtrar testes de import | precisão do Bandit: 51,7 % → 84,6 % |
| Tolerância de ±2 linhas no consenso | consenso: FP 14 → 4 |
| Mutação de containers (`append`) | +1 TP (`cleanup` em `hard_cases`) |
| Guardas de allowlist (`if x not in ALLOWED: abort`) | −2 FP potenciais (`next_page`, `run_report`) |
| Constantes de módulo em MAIÚSCULAS em SQL | −1 FP (`QUERY % TABLE`) |
| Resolução de `getattr` constante e shell implícito `sh -c` | −2 FN (recall 96 % → 100 %) |
| Valores de enumeração (`credentials: "same-origin"`) fora da regra de segredos | −1 FP (achado pelo dogfooding) |
