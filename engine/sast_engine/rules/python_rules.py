"""Regras determinísticas e heuristicas para Python, aplicadas sobre a AST.

Cada regra trabalha com nomes qualificados (aliases de import resolvidos), o que
evita falsos negativos como `from os import system as run_cmd`, e possui filtros
de contexto para reduzir falsos positivos (ex.: argumento literal constante).
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter

from ..models import Finding, Severity
from ..parsers.python_parser import ParsedModule
from .catalog import RULES

# ----------------------------------------------------------------- segredos
SECRET_NAME_RE = re.compile(
    r"(passw(or)?d|passwd|pwd|secret|token|api_?key|apikey|access_?key|private_?key|"
    r"client_?secret|auth_?key|credential|signing_?key|encryption_?key|"
    r"senha|segredo|credencia|chave_?(de_?)?(api|secreta|privada|acesso|criptografia))",  # nomes em português
    re.IGNORECASE,
)
NON_SECRET_NAME_RE = re.compile(
    r"_?(field|label|name|url|uri|prompt|msg|message|header|param|env|var|path|"
    r"file|len|length|type|pattern|regex|format|endpoint|id|column|attr|hint|"
    r"placeholder|policy|expir\w*|ttl|timeout|algorithm|mode)$|^(is_|has_|use_|min_|max_|num_)",
    re.IGNORECASE,
)
PLACEHOLDER_RE = re.compile(
    r"^(\$\{.*\}|<.*>|\{\{.*\}\}|%\(.*\)s|\*+|x+|\.+|your[_\- ].*|.*_here|example.*|"
    r"none|null|undefined|todo|fixme|redacted|n/a)$",
    re.IGNORECASE,
)
COMMON_WORDS = {"password", "passwd", "secret", "token", "api_key", "apikey", "pwd", "key", "bearer", "basic",
                "senha", "segredo", "chave", "usuario", "usuário"}

TOKEN_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "chave de acesso AWS"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "token do GitHub"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "token do Slack"),
    (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"), "chave privada"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{20,}"), "chave Stripe de produção"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "chave de API do Google"),
    (re.compile(r"sk-(proj-)?[A-Za-z0-9]{32,}"), "chave de API de LLM"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT"),
    (re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://[^:/\s@]+:[^@/\s]{3,}@[^/\s]+"), "string de conexão com senha"),
]

SQL_KEYWORDS_RE = re.compile(r"\b(select|insert\s+into|update|delete\s+from|drop\s+table|create\s+table|alter\s+table|where|union)\b", re.IGNORECASE)

SHELL_ALWAYS = {"os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4", "commands.getoutput",
                "commands.getstatusoutput", "subprocess.getoutput", "subprocess.getstatusoutput"}
SUBPROCESS_FUNCS = {"subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_call",
                    "subprocess.check_output"}
DESERIALIZERS = {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "_pickle.loads", "dill.load",
                 "dill.loads", "marshal.load", "marshal.loads", "shelve.open", "jsonpickle.decode",
                 "pandas.read_pickle", "yaml.unsafe_load", "torch.load"}
SAFE_YAML_LOADERS = {"yaml.SafeLoader", "yaml.CSafeLoader", "SafeLoader", "CSafeLoader", "yaml.BaseLoader"}
WEAK_HASHES = {"hashlib.md5", "hashlib.sha1", "Crypto.Hash.MD5.new", "Crypto.Hash.SHA.new", "Cryptodome.Hash.MD5.new"}
XML_UNSAFE_PREFIXES = ("xml.etree.ElementTree.", "xml.etree.cElementTree.", "xml.dom.minidom.", "xml.sax.",
                       "lxml.etree.", "xml.dom.pulldom.")
XML_UNSAFE_FUNCS = {"parse", "fromstring", "XML", "iterparse", "parseString", "make_parser", "XMLParser"}
WEAK_CIPHERS_RE = re.compile(r"(Crypto|Cryptodome)\.Cipher\.(DES3?|ARC2|ARC4|Blowfish|XOR)\.new$|"
                             r"algorithms\.(TripleDES|Blowfish|ARC4|IDEA|CAST5|SEED)$|modes\.ECB$")
HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "request"}
RANDOM_FUNCS = {"random.random", "random.randint", "random.choice", "random.choices", "random.getrandbits",
                "random.randrange", "random.sample", "random.uniform", "random.shuffle"}
TOKENISH_RE = re.compile(r"(token|passw|secret|otp|nonce|salt|session|api_?key|reset_?code|csrf)", re.IGNORECASE)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())


def is_constant_str(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_literal(node: ast.AST | None) -> bool:
    """True se a expressão for totalmente constante (sem variáveis)."""
    if node is None:
        return True
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(is_literal(e) for e in node.elts)
    if isinstance(node, ast.BinOp):
        return is_literal(node.left) and is_literal(node.right)
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in node.values)
    return False


def kw(call: ast.Call, name: str) -> ast.keyword | None:
    for k in call.keywords:
        if k.arg == name:
            return k
    return None


def kw_is(call: ast.Call, name: str, value: object) -> bool:
    k = kw(call, name)
    return k is not None and isinstance(k.value, ast.Constant) and k.value.value is value


def target_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript) and is_constant_str(node.slice):
        return node.slice.value  # type: ignore[attr-defined]
    return None


def looks_like_secret_value(value: str, name: str = "") -> bool:
    v = value.strip()
    if len(v) < 4 or " " in v or PLACEHOLDER_RE.match(v):
        return False
    if v.lower() in COMMON_WORDS or v.lower() == name.lower():
        return False
    # caminhos e URLs sem credencial embutida não são segredos
    return not (v.startswith(("/", "http://", "https://")) and "@" not in v)


def _sql_fragments(node: ast.AST) -> str:
    parts: list[str] = []
    for sub in ast.walk(node):
        if is_constant_str(sub):
            parts.append(sub.value)  # type: ignore[attr-defined]
    return " ".join(parts)


def _only_constants(node: ast.AST) -> bool:
    """`QUERY % TABLE` com nomes em MAIUSCULAS (constantes de módulo) não e entrada externa."""
    names = [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]
    others = [n for n in ast.walk(node) if isinstance(n, (ast.Call, ast.Attribute, ast.Subscript))]
    return bool(names) and not others and all(n.isupper() for n in names)


def is_dynamic_sql(node: ast.AST | None) -> bool:
    """f-string / % / + / .format contendo SQL e ao menos uma parte variável."""
    if node is None:
        return False
    dynamic = False
    if isinstance(node, ast.JoinedStr):
        dynamic = any(isinstance(v, ast.FormattedValue) for v in node.values) and not _only_constants(node)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        dynamic = not is_literal(node) and not _only_constants(node)
    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
          and node.func.attr == "format" and is_constant_str(node.func.value)):
        dynamic = bool(node.args or node.keywords)
    return dynamic and bool(SQL_KEYWORDS_RE.search(_sql_fragments(node)))


class PythonRuleVisitor(ast.NodeVisitor):
    def __init__(self, module: ParsedModule):
        self.m = module
        self.findings: list[Finding] = []
        self.suppressed = 0
        self._func_stack: list[str] = []
        self._dynamic_sql_vars: list[set[str]] = [set()]
        self._seen: set[tuple[str, int, int]] = set()

    # ------------------------------------------------------------- utilitarios
    def add(self, rule_id: str, node: ast.AST, message: str, severity: Severity | None = None,
            confidence: str = "HIGH") -> None:
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0)
        key = (rule_id, line, col)
        if key in self._seen:
            return
        self._seen.add(key)
        if self.m.is_suppressed(line):
            self.suppressed += 1
            return
        rule = RULES[rule_id]
        end_line = getattr(node, "end_lineno", None)
        self.findings.append(Finding(
            rule_id=rule_id,
            title=rule.title,
            message=message,
            severity=severity if severity is not None else rule.severity,
            cwe=rule.cwe,
            owasp=rule.owasp,
            file=self.m.path,
            line=line,
            column=col,
            end_line=end_line,
            snippet=self.m.snippet(line, end_line),
            confidence=confidence,
            engine="ast",
            remediation=rule.remediation,
        ))

    def q(self, node: ast.AST) -> str:
        return self.m.qualname(node) or ""

    # ------------------------------------------------------------- escopo
    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._check_default_secrets(node)
        self._func_stack.append(node.name)
        self._dynamic_sql_vars.append(set())
        self.generic_visit(node)
        self._dynamic_sql_vars.pop()
        self._func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def _check_default_secrets(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        args = node.args.args + node.args.kwonlyargs
        defaults = [None] * (len(node.args.args) - len(node.args.defaults)) + list(node.args.defaults) + list(node.args.kw_defaults)
        for arg, default in zip(args, defaults, strict=True):
            if default is not None and is_constant_str(default) and SECRET_NAME_RE.search(arg.arg) \
                    and not NON_SECRET_NAME_RE.search(arg.arg) and looks_like_secret_value(default.value, arg.arg):
                self.add("PY001", default, f"Parâmetro '{arg.arg}' possui credencial hardcoded como valor padrão.")

    # ------------------------------------------------------------- atribuicoes
    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check_assignment(target, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_assignment(node.target, node.value, node)
        self.generic_visit(node)

    def _check_assignment(self, target: ast.AST, value: ast.AST, node: ast.AST) -> None:
        name = target_name(target) or ""
        # PY001 - segredo por nome de variável
        if name and is_constant_str(value) and SECRET_NAME_RE.search(name) and not NON_SECRET_NAME_RE.search(name) \
                and looks_like_secret_value(value.value, name):  # type: ignore[attr-defined]
            self.add("PY001", node, f"Credencial atribuída diretamente a '{name}'.")
        # PY006 - rastreia variáveis que guardam SQL dinâmico
        if isinstance(target, ast.Name):
            if is_dynamic_sql(value):
                self._dynamic_sql_vars[-1].add(target.id)
            else:
                self._dynamic_sql_vars[-1].discard(target.id)
        # PY007 - DEBUG = True em settings
        if name == "DEBUG" and isinstance(value, ast.Constant) and value.value is True and not self._func_stack:
            self.add("PY007", node, "DEBUG = True definido no módulo de configuração.", confidence="MEDIUM")
        # PY008 - ctx.verify_mode = ssl.CERT_NONE / check_hostname = False
        if name == "verify_mode" and self.q(value).endswith("CERT_NONE"):
            self.add("PY008", node, "Contexto SSL configurado com CERT_NONE.")
        if name == "check_hostname" and isinstance(value, ast.Constant) and value.value is False:
            self.add("PY008", node, "Verificação de hostname TLS desabilitada.", severity=Severity.MEDIUM)
        # PY010 - random para valores sensíveis
        if name and TOKENISH_RE.search(name) and not NON_SECRET_NAME_RE.search(name):
            for sub in ast.walk(value):
                if isinstance(sub, ast.Call) and self.q(sub.func) in RANDOM_FUNCS:
                    self.add("PY010", sub, f"'{name}' gerado com {self.q(sub.func)}, que e previsível.")
                    break

    def visit_Dict(self, node: ast.Dict) -> None:
        for k, v in zip(node.keys, node.values, strict=True):
            if is_constant_str(k) and is_constant_str(v) and SECRET_NAME_RE.search(k.value) \
                    and not NON_SECRET_NAME_RE.search(k.value) and looks_like_secret_value(v.value, k.value):
                self.add("PY001", v, f"Credencial hardcoded na chave '{k.value}' do dicionario.")
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        # if password == "admin123"
        left = target_name(node.left) or ""
        if left and SECRET_NAME_RE.search(left) and not NON_SECRET_NAME_RE.search(left):
            for comp in node.comparators:
                if is_constant_str(comp) and looks_like_secret_value(comp.value, left):
                    self.add("PY001", comp, f"'{left}' comparado com credencial fixa no código.")
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and len(node.value) >= 16:
            for pattern, label in TOKEN_PATTERNS:
                if pattern.search(node.value):
                    self.add("PY001", node, f"String contém {label}.")
                    break

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        broad = node.type is None or self.q(node.type) in {"Exception", "BaseException"}
        if broad and len(node.body) == 1 and isinstance(node.body[0], (ast.Pass, ast.Continue)):
            self.add("PY015", node, "Exceção genérica capturada e descartada silenciosamente.")
        self.generic_visit(node)

    # ------------------------------------------------------------- chamadas
    def visit_Call(self, node: ast.Call) -> None:
        name = self.q(node.func)
        short = name.rsplit(".", 1)[-1]
        first = node.args[0] if node.args else None

        # PY001 - keyword args: connect(password="...")
        for k in node.keywords:
            if k.arg and SECRET_NAME_RE.search(k.arg) and not NON_SECRET_NAME_RE.search(k.arg) \
                    and is_constant_str(k.value) and looks_like_secret_value(k.value.value, k.arg):  # type: ignore[attr-defined]
                self.add("PY001", k.value, f"Credencial hardcoded passada em '{k.arg}=' para {name or 'função'}().")

        # PY002 - eval/exec/compile
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"} or (name == "compile" and len(node.args) >= 3):
            if is_literal(first):
                self.add("PY002", node, f"Uso de {short}() com argumento constante.", severity=Severity.LOW)
            else:
                self.add("PY002", node, f"{short}() executa uma expressão dinâmica.")

        # PY003 - comandos de sistema
        elif name in SHELL_ALWAYS:
            sev = Severity.LOW if is_literal(first) else Severity.HIGH
            self.add("PY003", node, f"{name}() executa o comando via shell.", severity=sev,
                     confidence="HIGH" if sev == Severity.HIGH else "MEDIUM")
        elif name in SUBPROCESS_FUNCS and kw_is(node, "shell", True):
            sev = Severity.LOW if is_literal(first) else Severity.HIGH
            self.add("PY003", node, f"{name}() chamado com shell=True.", severity=sev)

        # PY004 - desserialização
        elif name in DESERIALIZERS:
            if name == "torch.load" and kw_is(node, "weights_only", True):
                pass
            else:
                self.add("PY004", node, f"{name}() pode executar código durante a desserialização.")
        elif name == "yaml.load":
            loader = kw(node, "Loader")
            loader_name = self.q(loader.value) if loader else (self.q(node.args[1]) if len(node.args) > 1 else "")
            if loader_name not in SAFE_YAML_LOADERS:
                self.add("PY004", node, "yaml.load sem SafeLoader permite instanciar objetos arbitrarios.")

        # PY005 - hash fraco
        elif name in WEAK_HASHES and not kw_is(node, "usedforsecurity", False):
            self.add("PY005", node, f"{name.split('.')[-1] if '.' in name else name} e um hash criptograficamente fraco.")
        elif name == "hashlib.new" and is_constant_str(first) and first.value.lower() in {"md5", "sha1", "md4"}:  # type: ignore[union-attr]
            self.add("PY005", node, f"hashlib.new('{first.value}') usa hash fraco.")  # type: ignore[union-attr]

        # PY009 - mktemp
        elif name in {"tempfile.mktemp", "os.tempnam", "os.tmpnam"}:
            self.add("PY009", node, f"{name}() cria nome de arquivo temporário previsível.")

        # PY012 - XML
        elif name.startswith(XML_UNSAFE_PREFIXES) and short in XML_UNSAFE_FUNCS:
            self.add("PY012", node, f"{name}() não protege contra XXE/entity expansion.", confidence="MEDIUM")

        # PY013 - jinja2 autoescape / Markup
        elif name in {"jinja2.Environment", "jinja2.Template"}:
            ae = kw(node, "autoescape")
            if ae is None or (isinstance(ae.value, ast.Constant) and ae.value.value is False):
                self.add("PY013", node, f"{name} sem autoescape habilitado.", confidence="MEDIUM")
        elif name in {"markupsafe.Markup", "flask.Markup", "jinja2.Markup"} and first is not None and not is_literal(first):
            self.add("PY013", node, "Markup() marca conteúdo dinâmico como HTML seguro.")

        # PY014 - cifras fracas
        if WEAK_CIPHERS_RE.search(name):
            self.add("PY014", node, f"{name} e uma cifra/modo considerado inseguro.")
        elif name.endswith("AES.new") and any(self.q(a).endswith("MODE_ECB") for a in node.args):
            self.add("PY014", node, "AES em modo ECB não oculta padrões do texto claro.")

        # PY006 - SQL dinâmico
        if isinstance(node.func, ast.Attribute) and short in {"execute", "executemany", "executescript", "raw"} and first is not None:
            if is_dynamic_sql(first):
                self.add("PY006", node, "Consulta SQL construída dinamicamente e enviada ao banco.")
            elif isinstance(first, ast.Name) and first.id in self._dynamic_sql_vars[-1]:
                self.add("PY006", node, f"Variável '{first.id}' contém SQL montado com interpolação.")

        # PY007 - app.run(debug=True)
        if short == "run" and kw_is(node, "debug", True):
            self.add("PY007", node, "Aplicação iniciada com debug=True.")

        # PY008 - verify=False
        if kw_is(node, "verify", False) and (name.startswith(("requests.", "httpx.")) or short in HTTP_METHODS):
            self.add("PY008", node, f"{name or short}() com verify=False desabilita validação de certificado.")
        elif name == "ssl._create_unverified_context":
            self.add("PY008", node, "Contexto SSL sem verificação de certificado.")

        # PY011 - bind 0.0.0.0
        host = kw(node, "host")
        if host is not None and is_constant_str(host.value) and host.value.value == "0.0.0.0":  # type: ignore[attr-defined]  # nosec B104 - a regra apenas compara a string
            self.add("PY011", node, "Serviço configurado para escutar em 0.0.0.0.", confidence="MEDIUM")

        # PY016 - requests sem timeout
        if name.startswith("requests.") and short in HTTP_METHODS and kw(node, "timeout") is None:
            self.add("PY016", node, f"{name}() sem timeout.", confidence="MEDIUM")

        # PY010 - random dentro de função geradora de token
        if name in RANDOM_FUNCS and self._func_stack and TOKENISH_RE.search(self._func_stack[-1]):
            self.add("PY010", node, f"{name}() usado em '{self._func_stack[-1]}()', valor previsível.")

        self.generic_visit(node)


def run_python_rules(module: ParsedModule) -> tuple[list[Finding], int]:
    visitor = PythonRuleVisitor(module)
    visitor.visit(module.tree)
    return visitor.findings, visitor.suppressed
