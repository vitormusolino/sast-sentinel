# Testando a plataforma pessoalmente

Pré-requisito: a stack rodando (`docker compose up -d`) e o dashboard em http://localhost:8080.

**Login:** usuário `admin` e a senha definida em `ADMIN_PASSWORD` no `.env`. Se ela estiver vazia, a senha gerada aparece em `docker compose logs api`. Para criar contas de analista, use *Usuários* no menu.

## 4 formas de analisar código

| Forma | Como | Bom para |
|---|---|---|
| **Upload .zip** | Dashboard → *Varreduras* → *Upload .zip* | testar o fluxo completo com IA |
| **Repositório Git** | Dashboard → *Varreduras* → *Repositório Git* → cole a URL `https://github.com/...` (público) | projetos open source reais |
| **CLI em qualquer pasta** | veja abaixo | ciclo rápido "editar → analisar" |
| **API (Swagger)** | http://localhost:8000/docs → *Try it out* | mostrar a API na defesa |

### CLI sem instalar nada (só Docker)
Dentro da pasta que você quer analisar:

```powershell
docker run --rm -v "${PWD}:/code" sast-sentinel/api:latest sast scan /code -v
```

Com IA (usa o Ollama do compose):

```powershell
docker run --rm --network sast-sentinel_default -e OLLAMA_URL=http://ollama:11434 -v "${PWD}:/code" sast-sentinel/api:latest sast scan /code --ai -v
```

Outros formatos: acrescente `--format markdown` ou `--sarif /code/resultado.sarif`.

## Roteiro de testes (com resultado esperado)

Crie uma pasta, por exemplo `C:\teste-sast`, e trabalhe nela.

### 1. Detectar uma vulnerabilidade simples
`app.py`:
```python
import os
from flask import Flask, request
app = Flask(__name__)
SENHA_BANCO = "minhaSenha123"

@app.route("/arquivo")
def arquivo():
    nome = request.args.get("nome")
    os.system("cat " + nome)
    return "ok"
```
**Esperado:** `CRITICAL TAINT-CMDI app.py:9` (com o caminho source → sink), `HIGH PY001 app.py:4` e **Security Gate: FAILED** (código de saída 1).

### 2. Corrigir e ver o achado sumir
Troque a linha 9 por `subprocess.run(["cat", nome], check=True)` (adicione `import subprocess`) e a senha por `os.environ["SENHA_BANCO"]`.
**Esperado:** nenhum CRITICAL/HIGH e **Security Gate: PASSED**.

### 3. Sanitizador da categoria errada
```python
import shlex
nome = shlex.quote(request.args.get("nome"))
cursor.execute(f"SELECT * FROM t WHERE nome = '{nome}'")
```
**Esperado:** ainda é **SQL Injection**, porque `shlex.quote` protege shell e não SQL.

### 4. Fluxo entre arquivos
`repo.py`:
```python
def buscar(termo):
    return db.execute("SELECT * FROM u WHERE n = '" + termo + "'")
```
`app.py`:
```python
from repo import buscar
@app.route("/busca")
def busca():
    return buscar(request.args["q"])
```
**Esperado:** o achado aparece em `app.py`, com o caminho passando por `repo.py`.

### 5. Validação por allowlist (não deve alertar)
```python
PERMITIDOS = {"/home", "/perfil"}
destino = request.args.get("next")
if destino not in PERMITIDOS:
    abort(400)
return redirect(destino)
```
**Esperado:** nenhum Open Redirect. Apague as duas linhas do `if` e o alerta aparece.

### 6. Supressão justificada
Acrescente `# nosec - revisado pela equipe` no fim de uma linha com achado.
**Esperado:** o achado some e o resumo mostra `suprimidos: 1`.

### 7. Triagem persistente (dashboard)
Faça um scan, abra um achado, clique em **Marcar falso positivo** e faça o mesmo scan de novo (mesmo nome de projeto).
**Esperado:** o achado já vem marcado como falso positivo no scan novo.

### 8. Novos × corrigidos (dashboard)
Faça o scan do `samples/vulnerable_app.zip` e depois do `samples/safe_app.zip` **com o mesmo nome de projeto**.
**Esperado:** o segundo scan mostra vários "corrigidos" e o gráfico *Novos × corrigidos* se atualiza.

### 9. IA e correção verificada
Upload com *Triagem com IA* marcada. Abra um achado CRITICAL.
**Esperado:** a análise do Llama, o cenário de exploração e o código corrigido; o selo **✓ verificado pelo motor** quando o patch realmente resolve; e o motivo exato quando não resolve (ex.: "o motor ainda detecta PY002"). Em CPU, cada achado leva cerca de 1 min no LLM; repetir o mesmo scan usa o cache e leva segundos.

### 10. Repositório real
Em *Repositório Git*, use um projeto open source pequeno (ex.: `https://github.com/pallets/markupsafe`).
**Esperado:** clone, análise e gate em poucos segundos. Hosts fora da allowlist (ex.: `http://` ou um IP interno) são recusados.

## Código de terceiros (ex.: o professor quer testar algo dele)

| Origem | Como | Limites |
|---|---|---|
| Pasta local | compactar em .zip (botão direito → *Enviar para → Pasta compactada*) → *Upload .zip* | 50 MB compactado, 5.000 arquivos, 1 MB por arquivo |
| Repositório | *Repositório Git* → URL `https://` do GitHub, GitLab ou Bitbucket | apenas repositórios **públicos**; branch opcional |
| Pasta, pelo terminal | `docker run ... sast scan /code` (acima) | sem limite de tamanho |

- **Linguagens:**
  - **Python**: regras + taint interprocedural entre arquivos;
  - **Java**: regras + taint dentro de cada método (Servlet/Spring);
  - **JavaScript**: regras;
  - **Go, PHP, C#, TypeScript, Kotlin, Ruby, Rust, C/C++, Swift, Scala**: regras da comunidade Semgrep (precisa de internet no primeiro uso), com aviso no resultado;
  - outras linguagens: aviso de "não analisado" e gate **⚠ sem análise**, nunca "aprovado".
- **Repositório privado:** não é aceito (por segurança, credenciais na URL são recusadas). Alternativa: baixar o .zip pelo GitHub e enviar como upload.
- **Ética:** o código enviado é analisado só localmente (o LLM roda no Ollama da própria máquina) e o workspace é apagado ao fim do scan.

### 11. Relatório em PDF
Abra um scan e clique em **Baixar relatório (PDF)**.
**Esperado:** capa com o resultado do gate e as contagens por severidade, resumo executivo, tabela de todos os achados e, para cada crítico/alto, o código, o caminho do dado, como corrigir e (se houve IA) a análise e o código corrigido com o selo de verificação. O botão **SARIF** baixa o formato técnico, para ferramentas.

### 12. Segurança do login
- senha errada 5 vezes seguidas: na 6ª tentativa aparece "muitas tentativas" (bloqueio de 5 min);
- usuário inexistente: mesma mensagem de senha errada (não revela quem existe);
- crie um *analista* em *Usuários*, entre com ele em outra janela anônima: ele vê scans, mas não a gestão de usuários;
- clique em *Sair* e volte com o botão "voltar" do navegador: a API recusa (sessão revogada no servidor).

## Testes automatizados
```powershell
docker run --rm -v "${PWD}:/repo" -w /repo/engine sast-sentinel/api:latest sh -c "pip install -q pytest; python -m pytest -q -p no:cacheprovider"
```
Ou, com Python instalado: `pip install -e "engine[js,tools,dev]"` e depois `pytest engine/tests`.

## Bugs encontrados testando assim
Os testes manuais acharam dois problemas que os automatizados não pegavam, e ambos viraram testes de regressão:
- arquivos salvos com **BOM UTF-8** (padrão do Bloco de Notas/PowerShell) eram ignorados, e o gate aprovava código vulnerável;
- segredos com nomes em **português** (`SENHA_BANCO`, `chave_api`) não eram detectados.
