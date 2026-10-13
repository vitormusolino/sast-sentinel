"""Catálogo central de regras: metadados, mapeamento CWE/OWASP e remediação padrão.

A remediação daqui e usada como fallback determinístico quando o LLM local não
esta disponível, garantindo que todo achado tenha uma orientacao de correção.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Severity

A01 = "A01:2021-Broken Access Control"
A02 = "A02:2021-Cryptographic Failures"
A03 = "A03:2021-Injection"
A04 = "A04:2021-Insecure Design"
A05 = "A05:2021-Security Misconfiguration"
A07 = "A07:2021-Identification and Authentication Failures"
A08 = "A08:2021-Software and Data Integrity Failures"
A09 = "A09:2021-Security Logging and Monitoring Failures"
A10 = "A10:2021-Server-Side Request Forgery"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    cwe: str
    owasp: str
    severity: Severity
    description: str
    remediation: str
    example_fix: str = ""
    language: str = "python"
    engine: str = "ast"


RULES: dict[str, Rule] = {}


def _r(rule: Rule) -> Rule:
    RULES[rule.id] = rule
    return rule


# ---------------------------------------------------------------- Python / AST
_r(Rule("PY001", "Segredo hardcoded no código-fonte", "CWE-798", A07, Severity.HIGH,
        "Senha, token ou chave de API escrita diretamente no código. Qualquer pessoa com acesso ao repositório (ou ao histórico do Git) obtem a credencial.",
        "Mova o segredo para uma variável de ambiente ou cofre (Vault, AWS Secrets Manager) e revogue a credencial exposta.",
        'import os\nDB_PASSWORD = os.environ["DB_PASSWORD"]'))
_r(Rule("PY002", "Execução dinâmica de código (eval/exec)", "CWE-95", A03, Severity.HIGH,
        "eval/exec/compile executam texto como código Python. Com entrada externa, isso e execução remota de código.",
        "Evite eval/exec. Para literais use ast.literal_eval; para expressões, use um parser/whitelist explicito.",
        "import ast\nvalue = ast.literal_eval(user_value)"))
_r(Rule("PY003", "Execução de comando de sistema com shell", "CWE-78", A03, Severity.HIGH,
        "Comandos executados via shell (os.system, shell=True) permitem injeção de comandos quando parte da string e controlada externamente.",
        "Use subprocess.run com lista de argumentos e shell=False; valide entradas contra uma whitelist.",
        'import subprocess\nsubprocess.run(["ping", "-c", "1", host], shell=False, check=True)'))
_r(Rule("PY004", "Desserialização insegura", "CWE-502", A08, Severity.HIGH,
        "pickle/marshal/yaml.load podem instanciar objetos arbitrarios e executar código durante a desserialização.",
        "Use formatos de dados puros (json) ou yaml.safe_load. Nunca desserialize pickle de fontes não confiáveis.",
        "import json\ndata = json.loads(payload)"))
_r(Rule("PY005", "Algoritmo de hash fraco", "CWE-327", A02, Severity.MEDIUM,
        "MD5 e SHA-1 são vulneráveis a colisão e inadequados para senhas ou assinaturas.",
        "Use hashlib.sha256 para integridade e bcrypt/argon2/scrypt para senhas. Se o uso não for de segurança, passe usedforsecurity=False.",
        "import hashlib\ndigest = hashlib.sha256(data).hexdigest()"))
_r(Rule("PY006", "Consulta SQL montada com concatenação/formatacao", "CWE-89", A03, Severity.HIGH,
        "Montar SQL com f-string, %, + ou .format permite SQL Injection se algum valor vier do usuário.",
        "Use consultas parametrizadas (placeholders) do driver ou um ORM.",
        'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'))
_r(Rule("PY007", "Modo debug habilitado", "CWE-489", A05, Severity.MEDIUM,
        "Flask/Django em modo debug expoe console interativo e stack traces, permitindo execução de código.",
        "Controle o debug por variável de ambiente e mantenha-o desligado em produção.",
        'app.run(debug=os.getenv("FLASK_DEBUG") == "1")'))
_r(Rule("PY008", "Verificação TLS desabilitada", "CWE-295", A02, Severity.HIGH,
        "verify=False ou contexto SSL não verificado aceita qualquer certificado e permite ataques man-in-the-middle.",
        "Mantenha a verificação de certificado ativa; para CAs internas, passe o caminho do bundle em verify=.",
        'requests.get(url, timeout=10, verify="/etc/ssl/certs/ca-interna.pem")'))
_r(Rule("PY009", "Arquivo temporário inseguro (mktemp)", "CWE-377", A01, Severity.MEDIUM,
        "tempfile.mktemp retorna um nome previsível sem criar o arquivo, abrindo condição de corrida (TOCTOU).",
        "Use tempfile.NamedTemporaryFile ou tempfile.mkstemp.",
        "import tempfile\nwith tempfile.NamedTemporaryFile(delete=False) as tmp:\n    tmp.write(data)"))
_r(Rule("PY010", "Gerador aleatório inseguro para valor sensível", "CWE-330", A02, Severity.MEDIUM,
        "O módulo random e previsível e não deve gerar tokens, senhas ou chaves.",
        "Use o módulo secrets (secrets.token_urlsafe, secrets.token_hex).",
        "import secrets\ntoken = secrets.token_urlsafe(32)"))
_r(Rule("PY011", "Serviço exposto em todas as interfaces", "CWE-605", A05, Severity.LOW,
        "Bind em 0.0.0.0 expoe o serviço em todas as interfaces de rede.",
        "Faca bind em 127.0.0.1 por padrão e exponha via proxy reverso/container de forma explicita.",
        'app.run(host=os.getenv("HOST", "127.0.0.1"))'))
_r(Rule("PY012", "Parser XML vulnerável a XXE", "CWE-611", A05, Severity.MEDIUM,
        "Parsers XML da biblioteca padrão/lxml podem resolver entidades externas (XXE) e sofrer 'billion laughs'.",
        "Use a biblioteca defusedxml.",
        "import defusedxml.ElementTree as ET\ntree = ET.fromstring(xml_data)"))
_r(Rule("PY013", "Autoescape de template desabilitado", "CWE-79", A03, Severity.MEDIUM,
        "Templates Jinja2 sem autoescape renderizam HTML de usuário literalmente, permitindo XSS.",
        "Habilite autoescape (select_autoescape) e evite Markup() sobre dados externos.",
        'from jinja2 import Environment, select_autoescape\nenv = Environment(autoescape=select_autoescape(["html", "xml"]))'))
_r(Rule("PY014", "Cifra ou modo criptográfico fraco", "CWE-327", A02, Severity.HIGH,
        "DES, 3DES, RC4, Blowfish e modo ECB são considerados quebrados ou inseguros.",
        "Use AES-GCM (cryptography.hazmat.primitives.ciphers.aead.AESGCM) ou ChaCha20-Poly1305.",
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\naes = AESGCM(key)\nct = aes.encrypt(nonce, data, None)"))
_r(Rule("PY015", "Exceção silenciada (except: pass)", "CWE-703", A09, Severity.LOW,
        "Engolir exceções esconde falhas de segurança e dificulta auditoria.",
        "Capture exceções específicas e registre-as (logging) ou propague.",
        "except ValueError as exc:\n    logger.warning(\"valor inválido: %s\", exc)"))
_r(Rule("PY016", "Requisição HTTP sem timeout", "CWE-400", A05, Severity.LOW,
        "Chamadas HTTP sem timeout podem travar threads indefinidamente (negação de serviço).",
        "Sempre informe timeout= em requests/httpx.",
        "requests.get(url, timeout=10)"))

# ---------------------------------------------------------------- Taint analysis
_r(Rule("TAINT-SQLI", "SQL Injection (fluxo de dado não confiável)", "CWE-89", A03, Severity.CRITICAL,
        "Dado vindo do usuário chega a uma consulta SQL sem parametrizacao.",
        "Use placeholders do driver (cursor.execute(sql, params)) ou ORM; nunca interpole entrada do usuário no SQL.",
        'cursor.execute("SELECT * FROM users WHERE name = %s", (name,))', engine="taint"))
_r(Rule("TAINT-CMDI", "Command Injection (fluxo de dado não confiável)", "CWE-78", A03, Severity.CRITICAL,
        "Dado vindo do usuário chega a execução de comando do sistema operacional.",
        "Use lista de argumentos com shell=False, valide contra whitelist ou use shlex.quote.",
        'subprocess.run(["ping", "-c", "1", host], shell=False, check=True)', engine="taint"))
_r(Rule("TAINT-CODEI", "Code Injection (fluxo de dado não confiável)", "CWE-95", A03, Severity.CRITICAL,
        "Dado vindo do usuário chega a eval/exec.",
        "Remova eval/exec; use ast.literal_eval ou um mapeamento fixo de operações permitidas.",
        "import ast\nvalue = ast.literal_eval(expr)", engine="taint"))
_r(Rule("TAINT-PATH", "Path Traversal (fluxo de dado não confiável)", "CWE-22", A01, Severity.HIGH,
        "Dado vindo do usuário e usado como caminho de arquivo, permitindo ler/escrever fora do diretório esperado (../../etc/passwd).",
        "Normalize com os.path.realpath e verifique se o resultado esta dentro do diretório base; use secure_filename.",
        'base = os.path.realpath(UPLOAD_DIR)\npath = os.path.realpath(os.path.join(base, name))\nif not path.startswith(base + os.sep):\n    abort(400)', engine="taint"))
_r(Rule("TAINT-SSRF", "Server-Side Request Forgery", "CWE-918", A10, Severity.HIGH,
        "URL controlada pelo usuário e requisitada pelo servidor, permitindo acesso a rede interna/metadados de nuvem.",
        "Valide a URL contra uma allowlist de hosts e bloqueie IPs privados/link-local.",
        'if urlparse(url).hostname not in ALLOWED_HOSTS:\n    abort(400)\nrequests.get(url, timeout=5)', engine="taint"))
_r(Rule("TAINT-XSS", "Cross-Site Scripting refletido", "CWE-79", A03, Severity.HIGH,
        "Dado do usuário e devolvido em HTML/template sem escape.",
        "Use render_template com autoescape ou markupsafe.escape() antes de devolver o conteúdo.",
        "from markupsafe import escape\nreturn f\"<p>Ola {escape(name)}</p>\"", engine="taint"))
_r(Rule("TAINT-DESER", "Desserialização de dado não confiável", "CWE-502", A08, Severity.CRITICAL,
        "Payload do usuário e desserializado com pickle/yaml.load, permitindo execução remota de código.",
        "Use json.loads ou yaml.safe_load.",
        "data = json.loads(request.data)", engine="taint"))
_r(Rule("TAINT-REDIRECT", "Open Redirect", "CWE-601", A01, Severity.MEDIUM,
        "URL de redirecionamento controlada pelo usuário permite phishing.",
        "Redirecione apenas para caminhos relativos ou hosts de uma allowlist.",
        'target = request.args.get("next", "/")\nif urlparse(target).netloc:\n    target = "/"\nreturn redirect(target)', engine="taint"))
_r(Rule("TAINT-LOG", "Log Injection", "CWE-117", A09, Severity.LOW,
        "Dado do usuário gravado em log sem neutralizar quebras de linha permite forjar entradas.",
        "Use formatação parametrizada do logging e remova \\r\\n da entrada.",
        'logger.info("login de %s", username.replace("\\n", ""))', engine="taint"))

# ---------------------------------------------------------------- JavaScript / Tree-sitter
_r(Rule("JS001", "Uso de eval/Function em JavaScript", "CWE-95", A03, Severity.HIGH,
        "eval, new Function e setTimeout com string executam código arbitrario.",
        "Use JSON.parse para dados e funções reais em vez de strings.",
        "const data = JSON.parse(text);", language="javascript", engine="treesitter"))
_r(Rule("JS002", "Atribuição a innerHTML/outerHTML (DOM XSS)", "CWE-79", A03, Severity.HIGH,
        "Atribuir conteúdo dinâmico a innerHTML/outerHTML ou document.write permite XSS.",
        "Use textContent ou sanitize com DOMPurify.",
        "el.textContent = userValue;", language="javascript", engine="treesitter"))
_r(Rule("JS003", "child_process com string dinâmica", "CWE-78", A03, Severity.HIGH,
        "exec/execSync com template string ou concatenação permite command injection.",
        "Use execFile/spawn com array de argumentos.",
        "execFile('ping', ['-c', '1', host]);", language="javascript", engine="treesitter"))
_r(Rule("JS004", "Segredo hardcoded em JavaScript", "CWE-798", A07, Severity.HIGH,
        "Credencial escrita diretamente no código JavaScript.",
        "Leia de process.env e mantenha segredos fora do bundle do front-end.",
        "const apiKey = process.env.API_KEY;", language="javascript", engine="treesitter"))
_r(Rule("JS005", "SQL montado com template string", "CWE-89", A03, Severity.HIGH,
        "query() com template string/concatenacao permite SQL Injection.",
        "Use placeholders: db.query('SELECT * FROM u WHERE id = ?', [id]).",
        "db.query('SELECT * FROM users WHERE id = ?', [id]);", language="javascript", engine="treesitter"))


# ---------------------------------------------------------------- Java / Tree-sitter
_J = dict(language="java", engine="treesitter")
_r(Rule("JV001", "Execução de comando com string dinâmica (Java)", "CWE-78", A03, Severity.HIGH,
        "Runtime.exec()/ProcessBuilder com comando montado por concatenação permite command injection.",
        "Passe o comando como array de argumentos fixos e valide a entrada contra uma allowlist.",
        'new ProcessBuilder("ping", "-c", "1", host).start();', **_J))
_r(Rule("JV002", "SQL montado por concatenação (Java)", "CWE-89", A03, Severity.HIGH,
        "Statement.executeQuery/execute/createQuery com string concatenada permite SQL Injection.",
        "Use PreparedStatement com placeholders (?) ou parâmetros nomeados do JPA.",
        'PreparedStatement ps = conn.prepareStatement("SELECT * FROM u WHERE id = ?");\nps.setString(1, id);', **_J))
_r(Rule("JV003", "Segredo hardcoded (Java)", "CWE-798", A07, Severity.HIGH,
        "Credencial escrita diretamente no código Java.",
        "Leia de variável de ambiente (System.getenv) ou de um cofre de segredos.",
        'String dbPassword = System.getenv("DB_PASSWORD");', **_J))
_r(Rule("JV004", "Hash fraco (Java)", "CWE-327", A02, Severity.MEDIUM,
        "MessageDigest com MD5/SHA-1 é vulnerável a colisões.",
        "Use SHA-256 para integridade e BCrypt/Argon2 (Spring Security) para senhas.",
        'MessageDigest md = MessageDigest.getInstance("SHA-256");', **_J))
_r(Rule("JV005", "Cifra ou modo fraco (Java)", "CWE-327", A02, Severity.HIGH,
        "DES/3DES/RC4/Blowfish ou modo ECB (inclusive \"AES\" sem modo, que usa ECB por padrão).",
        "Use AES/GCM/NoPadding com IV aleatório.",
        'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");', **_J))
_r(Rule("JV006", "Desserialização insegura (Java)", "CWE-502", A08, Severity.HIGH,
        "ObjectInputStream/XMLDecoder sobre dados externos permite execução remota de código (gadget chains).",
        "Evite serialização nativa; use JSON (Jackson sem default typing) ou um ObjectInputFilter restritivo.",
        "MyDto dto = new ObjectMapper().readValue(json, MyDto.class);", **_J))
_r(Rule("JV007", "Parser XML vulnerável a XXE (Java)", "CWE-611", A05, Severity.MEDIUM,
        "Factories XML do JDK resolvem entidades externas por padrão.",
        "Desabilite DOCTYPE: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true).",
        'dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);', **_J))
_r(Rule("JV008", "Random inseguro para valor sensível (Java)", "CWE-330", A02, Severity.MEDIUM,
        "java.util.Random e Math.random são previsíveis.",
        "Use java.security.SecureRandom.",
        "byte[] token = new byte[32];\nnew SecureRandom().nextBytes(token);", **_J))
_r(Rule("JV009", "Validação TLS desabilitada (Java)", "CWE-295", A02, Severity.HIGH,
        "TrustManager vazio ou HostnameVerifier que retorna true aceita qualquer certificado (MITM).",
        "Use o TrustManager padrão da JVM; para CAs internas, importe o certificado no truststore.",
        "// remova o TrustManager customizado e use o SSLContext padrão", **_J))


def get_rule(rule_id: str) -> Rule | None:
    return RULES.get(rule_id)


# Remediação genérica por CWE (usada para achados vindos de Bandit/Semgrep)
CWE_REMEDIATION: dict[str, str] = {r.cwe: r.remediation for r in RULES.values()}
