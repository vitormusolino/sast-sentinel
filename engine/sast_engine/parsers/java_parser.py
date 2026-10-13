"""Análise de Java usando Tree-sitter.

Duas camadas, como no Python:
* **regras de padrão** (JV001-JV009) sobre a CST: exec dinâmico, SQL concatenado,
  segredos, hash/cifra fracos, desserialização, XXE, random inseguro, TLS "trust-all";
* **taint intraprocedural**: dentro de cada método, rastreia dados vindos de
  `request.getParameter(...)`, `@RequestParam`/`@PathVariable`/`@RequestBody` etc.
  até sinks (`executeQuery`, `Runtime.exec`, `new File`, `sendRedirect`,
  `getWriter().print`...), respeitando sanitizadores (`Integer.parseInt`, encoders).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..models import Finding, TraceStep
from ..rules.catalog import RULES
from ..rules.python_rules import NON_SECRET_NAME_RE, SECRET_NAME_RE, TOKEN_PATTERNS, looks_like_secret_value

try:  # pragma: no cover - depende do ambiente
    import tree_sitter_java as _tsjava
    from tree_sitter import Language, Parser

    _JAVA_LANGUAGE = Language(_tsjava.language())
    JAVA_AVAILABLE = True
except Exception:  # noqa: BLE001
    _JAVA_LANGUAGE = None
    JAVA_AVAILABLE = False

JAVA_EXTENSIONS = (".java",)
SUPPRESS_RE = re.compile(r"//\s*(nosec|sast-ignore)\b", re.IGNORECASE)
SQL_RE = re.compile(r"(?i)\b(select|insert\s+into|update|delete\s+from|where)\b")

# ------------------------------------------------------------------- taint
SOURCE_METHODS = {"getParameter", "getParameterValues", "getParameterMap", "getHeader", "getHeaders",
                  "getQueryString", "getCookies", "getInputStream", "getReader", "getRequestURI", "getPathInfo"}
SOURCE_ANNOTATIONS = {"RequestParam", "PathVariable", "RequestBody", "RequestHeader", "CookieValue",
                      "ModelAttribute", "QueryParam", "PathParam", "FormParam"}
SANITIZERS = {"parseInt", "parseLong", "parseDouble", "valueOf", "escapeHtml4", "escapeSql", "forHtml",
              "forJavaScript", "encodeForHTML", "encodeForSQL", "getName", "normalize", "matches",
              "htmlEscape", "escapeHtml", "escapeXml", "sanitize", "encode"}
# sink -> (regra, descrição)
SINK_METHODS = {
    "executeQuery": "TAINT-SQLI", "executeUpdate": "TAINT-SQLI", "execute": "TAINT-SQLI", "addBatch": "TAINT-SQLI",
    "prepareStatement": "TAINT-SQLI", "createQuery": "TAINT-SQLI", "createNativeQuery": "TAINT-SQLI",
    "queryForList": "TAINT-SQLI", "queryForObject": "TAINT-SQLI",
    "exec": "TAINT-CMDI",
    "sendRedirect": "TAINT-REDIRECT",
    "getForObject": "TAINT-SSRF", "getForEntity": "TAINT-SSRF",
}
SINK_CONSTRUCTORS = {
    "File": "TAINT-PATH", "FileInputStream": "TAINT-PATH", "FileReader": "TAINT-PATH",
    "FileOutputStream": "TAINT-PATH", "FileWriter": "TAINT-PATH", "ProcessBuilder": "TAINT-CMDI", "URL": "TAINT-SSRF",
}
WRITER_METHODS = {"print", "println", "write", "append"}


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def _walk(node) -> Iterator:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _args(node) -> list:
    args = node.child_by_field_name("arguments")
    return [c for c in args.children if c.is_named and c.type != "comment"] if args is not None else []


def _string_value(node) -> str | None:
    if node is None or node.type != "string_literal":
        return None
    raw = _text(node)
    return raw[1:-1] if len(raw) >= 2 else ""


def _is_dynamic(node, numeric: frozenset[str] = frozenset()) -> bool:
    """Expressão que não é só literal (concatenação com variável, chamada, identificador).

    `numeric`: variáveis declaradas com tipo primitivo numérico (int, long...). Como Java é
    tipado estaticamente, concatenar um `int` no SQL não injeta texto do atacante."""
    if node is None:
        return False
    if node.type in {"string_literal", "character_literal", "decimal_integer_literal", "true", "false", "null_literal"}:
        return False
    if node.type == "identifier" and _text(node) in numeric:
        return False
    if node.type in {"binary_expression", "parenthesized_expression"}:
        return any(_is_dynamic(c, numeric) for c in node.children if c.is_named)
    return True


def _numeric_variables(root) -> frozenset[str]:
    names = set()
    for node in _walk(root):
        if node.type in {"local_variable_declaration", "field_declaration", "formal_parameter"}:
            typ = node.child_by_field_name("type")
            if typ is not None and typ.type in {"integral_type", "floating_point_type", "boolean_type"}:
                if node.type == "formal_parameter":
                    names.add(_text(node.child_by_field_name("name")))
                else:
                    names.update(_text(d.child_by_field_name("name")) for d in node.children
                                 if d.type == "variable_declarator")
    return frozenset(names)


class JavaAnalyzer:
    def __init__(self, path: str, source: str):
        self.path = path
        self.source = source
        self.lines = source.splitlines()
        self.findings: list[Finding] = []
        self.suppressed = 0
        self._seen: set[tuple[str, int]] = set()
        self._xxe_hardened = any(k in source for k in ("disallow-doctype-decl", "FEATURE_SECURE_PROCESSING",
                                                       "SUPPORT_DTD", "external-general-entities"))

    # ------------------------------------------------------------ util
    def add(self, rule_id: str, node, message: str, trace: list[TraceStep] | None = None,
            confidence: str = "MEDIUM") -> None:
        line = node.start_point[0] + 1
        if (rule_id, line) in self._seen:
            return
        self._seen.add((rule_id, line))
        if line - 1 < len(self.lines) and SUPPRESS_RE.search(self.lines[line - 1]):
            self.suppressed += 1
            return
        rule = RULES[rule_id]
        self.findings.append(Finding(
            rule_id=rule_id, title=rule.title, message=message, severity=rule.severity, cwe=rule.cwe,
            owasp=rule.owasp, file=self.path, line=line, column=node.start_point[1],
            end_line=node.end_point[0] + 1,
            snippet=self.lines[line - 1].strip() if line - 1 < len(self.lines) else "",
            confidence=confidence, engine="taint" if trace else "treesitter", trace=trace or [],
            remediation=rule.remediation,
        ))

    def run(self) -> None:
        tree = Parser(_JAVA_LANGUAGE).parse(self.source.encode("utf-8"))
        self._numeric = _numeric_variables(tree.root_node)
        for node in _walk(tree.root_node):
            handler = getattr(self, f"_on_{node.type}", None)
            if handler:
                handler(node)
            if node.type in {"method_declaration", "constructor_declaration"}:
                MethodTaint(self, node).run()

    # ------------------------------------------------------------ regras de padrão
    def _on_method_invocation(self, node) -> None:
        name = _text(node.child_by_field_name("name"))
        obj = _text(node.child_by_field_name("object"))
        args = _args(node)
        first = args[0] if args else None
        if name == "exec" and ("getRuntime" in obj or "Runtime" in obj) and _is_dynamic(first):
            self.add("JV001", node, "Runtime.exec() com comando montado dinamicamente.")
        elif name in SINK_METHODS and SINK_METHODS[name] == "TAINT-SQLI" and first is not None \
                and first.type == "binary_expression" and _is_dynamic(first, self._numeric) \
                and SQL_RE.search(_text(first)):
            self.add("JV002", node, f".{name}() recebe SQL montado por concatenação.")
        elif name == "getInstance" and obj.endswith("MessageDigest"):
            algo = (_string_value(first) or "").upper()
            if algo in {"MD5", "MD2", "SHA-1", "SHA1", "SHA"}:
                self.add("JV004", node, f"MessageDigest.getInstance(\"{algo}\") usa hash fraco.")
        elif name == "getInstance" and obj.endswith("Cipher"):
            algo = (_string_value(first) or "").upper()
            if re.match(r"^(DES|DESEDE|RC4|RC2|BLOWFISH|ARCFOUR)\b", algo) or "/ECB/" in algo or algo == "AES":
                self.add("JV005", node, f"Cipher.getInstance(\"{algo}\") usa cifra ou modo inseguro"
                         + (" (\"AES\" sozinho usa ECB por padrão)" if algo == "AES" else "") + ".")
        elif name == "newInstance" and obj.split(".")[-1] in {"DocumentBuilderFactory", "SAXParserFactory",
                                                               "XMLInputFactory", "TransformerFactory"}:
            if not self._xxe_hardened:
                self.add("JV007", node, f"{obj}.newInstance() sem desabilitar DTD/entidades externas (XXE).")
        elif name in {"setHostnameVerifier", "setDefaultHostnameVerifier"} and first is not None \
                and re.search(r"->\s*true", _text(first)):
            self.add("JV009", node, "HostnameVerifier que aceita qualquer host.")

    def _on_object_creation_expression(self, node) -> None:
        typ = _text(node.child_by_field_name("type"))
        args = _args(node)
        if typ in {"ObjectInputStream", "XMLDecoder"}:
            self.add("JV006", node, f"new {typ}() desserializa objetos arbitrários.")
        elif typ == "ProcessBuilder" and args and any(_is_dynamic(a) for a in args) \
                and any(a.type == "binary_expression" for a in args):
            self.add("JV001", node, "ProcessBuilder com comando montado por concatenação.")

    def _on_variable_declarator(self, node) -> None:
        name = _text(node.child_by_field_name("name"))
        value = node.child_by_field_name("value")
        literal = _string_value(value)
        if literal is not None and SECRET_NAME_RE.search(name) and not NON_SECRET_NAME_RE.search(name) \
                and looks_like_secret_value(literal, name):
            self.add("JV003", node, f"Credencial hardcoded em '{name}'.", confidence="HIGH")
        if value is not None and re.search(r"(token|senha|password|secret|otp|nonce|salt)", name, re.I) \
                and re.search(r"new\s+Random\s*\(|Math\.random\s*\(", _text(value)):
            self.add("JV008", node, f"'{name}' gerado com java.util.Random/Math.random (previsível).")

    def _on_string_literal(self, node) -> None:
        value = _string_value(node) or ""
        if len(value) >= 16:
            for pattern, label in TOKEN_PATTERNS:
                if pattern.search(value):
                    self.add("JV003", node, f"String contém {label}.", confidence="HIGH")
                    return

    def _on_method_declaration(self, node) -> None:
        name = _text(node.child_by_field_name("name"))
        body = node.child_by_field_name("body")
        if name in {"checkServerTrusted", "checkClientTrusted"} and body is not None \
                and not [c for c in body.children if c.is_named and c.type != "comment"]:
            self.add("JV009", node, f"{name}() vazio: aceita qualquer certificado (trust-all).")


class MethodTaint:
    """Taint intraprocedural sensível à ordem dentro de um método Java."""

    def __init__(self, analyzer: JavaAnalyzer, method):
        self.a = analyzer
        self.method = method
        self.tainted: dict[str, list[TraceStep]] = {}

    def _step(self, node, desc: str) -> TraceStep:
        return TraceStep(self.a.path, node.start_point[0] + 1, desc)

    def run(self) -> None:
        params = self.method.child_by_field_name("parameters")
        for p in (params.children if params is not None else []):
            if p.type != "formal_parameter":
                continue
            annotations = {_text(a.child_by_field_name("name")) for a in _walk(p)
                           if a.type in {"annotation", "marker_annotation"}}
            if annotations & SOURCE_ANNOTATIONS:
                pname = _text(p.child_by_field_name("name"))
                self.tainted[pname] = [self._step(p, f"Source: parâmetro HTTP '{pname}' "
                                                     f"(@{sorted(annotations & SOURCE_ANNOTATIONS)[0]})")]
        body = self.method.child_by_field_name("body")
        if body is None:
            return
        # 1ª passada propaga dependências de laços; na 2ª os sinks são checados na ordem do código
        for final in (False, True):
            for node in _walk(body):
                if node.type == "variable_declarator":
                    self._assign(_text(node.child_by_field_name("name")), node.child_by_field_name("value"))
                elif node.type == "assignment_expression":
                    left = node.child_by_field_name("left")
                    if left is not None and left.type == "identifier":
                        self._assign(_text(left), node.child_by_field_name("right"), node)
                elif final and node.type == "method_invocation":
                    self._check_method_sink(node)
                elif final and node.type == "object_creation_expression":
                    self._check_constructor_sink(node)

    def _assign(self, name: str, value, node=None) -> None:
        if value is None:
            return
        trace = self.trace_of(value)
        if trace is not None:
            if name not in self.tainted:
                self.tainted[name] = trace + [self._step(node or value, f"Atribuído a '{name}'")]
        else:
            self.tainted.pop(name, None)  # reatribuição com valor limpo

    def trace_of(self, node) -> list[TraceStep] | None:
        """Caminho de taint da expressão (None se não contaminada)."""
        if node is None:
            return None
        if node.type == "identifier":
            return self.tainted.get(_text(node))
        if node.type in {"string_literal", "decimal_integer_literal", "true", "false", "null_literal"}:
            return None
        if node.type == "method_invocation":
            name = _text(node.child_by_field_name("name"))
            if name in SOURCE_METHODS:
                return [self._step(node, f"Source: {name}() da requisição HTTP")]
            if name in SANITIZERS:
                return None
        if node.type in {"lambda_expression", "class_body"}:
            return None
        for child in node.children:
            if child.is_named:
                t = self.trace_of(child)
                if t is not None:
                    return t
        return None

    def _report(self, rule_id: str, node, sink: str, trace: list[TraceStep]) -> None:
        full = trace + [self._step(node, f"Sink: {sink}")]
        source = trace[0].description.replace("Source: ", "")
        self.a.add(rule_id, node, f"Dado não confiável ({source}) alcança {sink} sem sanitização adequada.",
                   trace=full, confidence="HIGH")

    def _check_method_sink(self, node) -> None:
        name = _text(node.child_by_field_name("name"))
        obj = _text(node.child_by_field_name("object"))
        args = _args(node)
        if name in WRITER_METHODS and "getWriter" in obj:
            rule = "TAINT-XSS"
        elif name in SINK_METHODS:
            rule = SINK_METHODS[name]
        elif name == "get" and obj in {"Paths", "Path", "java.nio.file.Paths"}:
            rule = "TAINT-PATH"
        else:
            return
        if not args:
            return
        trace = self.trace_of(args[0])
        if trace is not None:
            self._report(rule, node, f"{obj + '.' if obj else ''}{name}()", trace)

    def _check_constructor_sink(self, node) -> None:
        typ = _text(node.child_by_field_name("type"))
        if typ not in SINK_CONSTRUCTORS:
            return
        for arg in _args(node):
            trace = self.trace_of(arg)
            if trace is not None:
                self._report(SINK_CONSTRUCTORS[typ], node, f"new {typ}()", trace)
                return


def analyze_java(path: str, source: str) -> tuple[list[Finding], int]:
    if not JAVA_AVAILABLE:
        return [], 0
    analyzer = JavaAnalyzer(path, source)
    analyzer.run()
    return analyzer.findings, analyzer.suppressed
