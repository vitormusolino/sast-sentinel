# Motor SAST: parsing, regras e taint analysis

## 1. Parsing

### Python (`ast`)
O módulo `ast` da biblioteca padrão gera a **Árvore de Sintaxe Abstrata** exata do interpretador, sem heurística de tokenização. Sobre ela, o parser:

- **resolve aliases de import**: `from os import system as run_cmd; run_cmd(x)` vira `os.system`, e `import subprocess as sp; sp.Popen` vira `subprocess.Popen`. Sem isso, renomear um import bastaria para "esconder" a vulnerabilidade, um falso negativo clássico de ferramentas baseadas em regex;
- coleta comentários de supressão (`# nosec`, `# sast: ignore`) com o `tokenize`, para que uma string contendo "nosec" não suprima nada;
- gera trechos e contexto numerado para o relatório e para o prompt da IA.

### JavaScript (Tree-sitter)
O Tree-sitter produz uma **CST** (árvore de sintaxe concreta) incremental e tolerante a erros, a mesma tecnologia usada pelo GitHub e pelo Neovim. As regras percorrem os nós (`call_expression`, `assignment_expression`, `new_expression`, `jsx_attribute`...). Como o Tree-sitter suporta dezenas de linguagens com a mesma API, adicionar Java exige só a gramática e as regras.

### Java (Tree-sitter)
Mesma infraestrutura do JS, com a gramática `tree-sitter-java`:
- **9 regras** (JV001–JV009): `Runtime.exec`/`ProcessBuilder` dinâmico, SQL concatenado, segredos, `MessageDigest` MD5/SHA-1, `Cipher` DES/ECB (inclusive `"AES"` sozinho, que usa ECB), `ObjectInputStream`, XXE em factories XML (a menos que o arquivo desabilite DTD), `java.util.Random` para tokens e TLS "trust-all";
- **taint intraprocedural**: fontes Servlet (`getParameter`, `getHeader`, `getInputStream`...) e Spring/JAX-RS (`@RequestParam`, `@PathVariable`, `@RequestBody`...); sinks `executeQuery/execute/createQuery`, `exec`, `new File/FileInputStream`, `Paths.get`, `sendRedirect`, `getWriter().print`, `new URL`; sanitizadores `Integer.parseInt`, `HtmlUtils.htmlEscape`, encoders OWASP;
- **uso do sistema de tipos**: variáveis declaradas `int/long/double` concatenadas em SQL não são reportadas. É algo que em Python (tipagem dinâmica) não dá para saber.

### Outras linguagens (fallback Semgrep)
Para Go, PHP, C#, TypeScript, Kotlin, Ruby, Rust, C/C++, Swift e Scala, o scanner chama o Semgrep com o pacote de regras da comunidade da linguagem (`p/golang`, `p/php`...), só nos arquivos dela. O resultado aparece com um aviso explícito ("analisado apenas com regras da comunidade, sem taint nem IA verificada"). Se o Semgrep não estiver disponível ou não houver internet para baixar as regras, o scan avisa e o gate fica **sem análise**, nunca "aprovado".

## 2. Regras determinísticas e heurísticas

| ID | Regra | CWE | Filtros anti-falso-positivo |
|---|---|---|---|
| PY001 | Segredo hardcoded | 798 | ignora nomes como `*_field`, `*_url`, `*_env`, `*_label`; placeholders (`your-key-here`, `${VAR}`); valores com espaço; valor igual ao nome. Detecta também padrões de token (AWS `AKIA…`, GitHub `ghp_…`, Stripe, JWT, chave privada, string de conexão com senha) |
| PY002 | `eval`/`exec` | 95 | argumento literal constante cai para LOW |
| PY003 | Comando via shell | 78 | `subprocess` só com `shell=True`; argumento literal cai para LOW |
| PY004 | Desserialização insegura | 502 | `yaml.load` com `SafeLoader` é aceito; `torch.load(weights_only=True)` é aceito |
| PY005 | Hash fraco (MD5/SHA-1) | 327 | `usedforsecurity=False` é aceito |
| PY006 | SQL com interpolação | 89 | acompanha variáveis que guardam SQL dinâmico; ignora constantes de módulo em MAIÚSCULAS |
| PY007 | Debug habilitado | 489 | `debug=True` e `DEBUG = True` |
| PY008 | TLS sem verificação | 295 | `verify=False`, `CERT_NONE`, `check_hostname=False` |
| PY009 | `mktemp` | 377 | — |
| PY010 | `random` para segredo | 330 | só quando o destino ou a função tem nome de token/senha/OTP |
| PY011 | Bind em 0.0.0.0 | 605 | — |
| PY012 | XML vulnerável a XXE | 611 | — |
| PY013 | Jinja2 sem autoescape / `Markup` dinâmico | 79 | — |
| PY014 | Cifra fraca / ECB | 327 | — |
| PY015 | `except: pass` | 703 | só exceções genéricas |
| PY016 | HTTP sem timeout | 400 | — |
| JS001–JS005 | eval, innerHTML, child_process, segredo, SQL | 95, 79, 78, 798, 89 | conteúdo literal é ignorado |

Todas as regras estão mapeadas para **CWE** e **OWASP Top 10 2021** em `rules/catalog.py`, com remediação e exemplo de código corrigido.

## 3. Taint analysis

### Modelo

```
SOURCE ──► propagação ──► [SANITIZER?] ──► SINK
request.args.get   f-string, +, .format,    shlex.quote (só CWE-78)   cursor.execute
input(), sys.argv  atribuição, listas,      int() (todas)             os.system / eval
<rota Flask>       retorno de função,       html.escape (só CWE-79)   open / send_file
FastAPI params     loops, with, try         secure_filename (CWE-22)  requests.get
```

- **~25 sources**: Flask (`request.args/form/json/cookies/headers/files`), Django (`request.GET/POST/body`), FastAPI/Starlette (parâmetros de rota, `query_params`), `input()`, `sys.argv`. Parâmetros de rota com conversor `<int:id>` **não** são fontes, porque o framework já garante que são inteiros.
- **~45 sinks** em 8 categorias: SQLi (89), Command Injection (78), Code Injection (95), Path Traversal (22), SSRF (918), XSS (79, inclusive `return f"<p>{x}</p>"` em rotas), desserialização (502), Open Redirect (601) e Log Injection (117).
- **Sanitizadores por categoria**: cada um declara *quais* CWEs neutraliza. `shlex.quote(x)` usado em SQL continua sendo SQL Injection, um erro real e comum que ferramentas simples não percebem.

### Despacho dinâmico e shell implícito
- `getattr(os, "system")(cmd)` e `runner = getattr(os, "system"); runner(cmd)` são resolvidos para `os.system`;
- `subprocess.run(["sh", "-c", cmd])` (também `bash`, `cmd /c`, `powershell -Command`) é tratado como `shell=True`.

### Sensibilidade ao fluxo
A análise percorre as instruções **em ordem**:
- **reatribuição mata o taint**: em `x = request.args["x"]; x = "fixo"; os.system(x)` não há achado;
- **`if/else`** analisa os dois ramos e une os estados (análise *may*);
- **loops** são percorridos duas vezes para propagar dependências entre iterações;
- **containers**: `lista.append(tainted)` contamina a lista; `d["k"] = tainted` contamina o dicionário;
- **guardas de validação**: `if x not in ALLOWED: abort(400)` e `if not re.fullmatch(P, x): return` limpam `x` depois do `if`; `if x in ALLOWED:` limpa `x` dentro do bloco.

### Interprocedural (resumos de função)
Para cada função o motor calcula um **resumo**:
- `returns_from[i]`: o parâmetro *i* contamina o retorno? com quais sanitizações acumuladas?
- `sinks_from[i]`: o parâmetro *i* chega a quais sinks? com qual caminho?

Os resumos são calculados por **iteração de ponto fixo** (até estabilizar, no máximo 4 rodadas), o que cobre cadeias `view → service → repository → execute` e funciona **entre arquivos**. Quando uma rota chama `find_user_by_name(term)`, o achado aparece na linha da chamada com o caminho completo:

```
app.py:38  Source: parâmetro de query string
app.py:39  Passado para find_user_by_name() como parâmetro 'name'
db.py:12   Atribuído a 'query'
db.py:13   Sink: conn.execute()
```

Funções que sanitizam (`def to_int(v): return int(v)`) produzem um resumo vazio, e o chamador fica limpo automaticamente.

Para evitar confusões, o resumo só é aplicado quando a chamada resolve para o projeto: chamada direta (`f(x)`), `self.metodo(x)` ou `modulo.f(x)` com módulo correspondente. Assim, `dict.get()` não é confundido com uma função `get()` do projeto.

### Severidade contextual
Fontes locais (`input()`, `sys.argv`) reduzem a severidade em um nível e a confiança para MEDIUM: o "atacante" de uma CLI já controla a máquina.

## 4. Consenso e deduplicação

O mesmo problema costuma ser apontado por vários motores (taint + regra AST + Bandit). O scanner:
1. agrupa por `(arquivo, linha, CWE)`, com tolerância de ±2 linhas para ferramentas externas (o Bandit aponta onde o SQL é montado; nós, onde ele é executado);
2. mantém o achado mais rico (prioridade `taint > ast > treesitter > semgrep > bandit`);
3. registra `confirmed_by` e eleva a confiança para HIGH.

O CWE do Bandit é **normalizado** (ex.: B105 usa CWE-259 e nós usamos CWE-798; B307/`eval` usa CWE-78 e o correto é CWE-95), e testes que só sinalizam *imports* (B403/B404) ou o padrão seguro (B603) são descartados como ruído. Só essa normalização elevou a precisão do Bandit de 52 % para 85 % no nosso corpus.

## 5. Limitações conhecidas (e por quê)

| Limitação | Exemplo | Mitigação / trabalho futuro |
|---|---|---|
| Despacho dinâmico com nome **calculado** | `getattr(os, nome_vindo_do_banco)(cmd)` | `getattr` com string **constante** e aliases (`runner = os.system`) já são resolvidos |
| Validação semântica | `if urlparse(u).netloc: u = "/"` | a triagem por LLM reconhece; modelar mais validadores |
| Ponteiros/aliasing complexos | objetos mutados por referência em outra função | análise de alias (pointer analysis) |
| Nomes de função duplicados em módulos diferentes | dois `save()` | resumos indexados por módulo + nome |
| Taint em JavaScript | — | o JS hoje tem apenas regras; o taint seria a evolução natural com Tree-sitter |

Esses casos estão **no corpus** (`samples/hard_cases`) e aparecem honestamente como FP/FN no [benchmark](BENCHMARK.md).
