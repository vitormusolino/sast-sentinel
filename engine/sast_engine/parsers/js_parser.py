"""Análise de JavaScript/TypeScript usando Tree-sitter (parser incremental, CST).

Tree-sitter e opcional: se a biblioteca não estiver instalada, arquivos JS são
ignorados e o scanner registra um aviso (o motor Python continua funcionando).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..models import Finding
from ..rules.catalog import RULES
from ..rules.python_rules import NON_SECRET_NAME_RE, SECRET_NAME_RE, TOKEN_PATTERNS, looks_like_secret_value

try:  # pragma: no cover - depende do ambiente
    import tree_sitter_javascript as _tsjs
    from tree_sitter import Language, Parser

    _JS_LANGUAGE = Language(_tsjs.language())
    TREE_SITTER_AVAILABLE = True
except Exception:  # noqa: BLE001
    _JS_LANGUAGE = None
    TREE_SITTER_AVAILABLE = False

JS_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs")
SUPPRESS_RE = re.compile(r"//\s*(nosec|sast-ignore)\b", re.IGNORECASE)
EXEC_FUNCS = {"exec", "execSync", "child_process.exec", "child_process.execSync", "cp.exec", "cp.execSync",
              "childProcess.exec", "childProcess.execSync"}
SQL_METHODS = {"query", "raw", "execute", "$queryRawUnsafe", "$executeRawUnsafe"}


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def _walk(node) -> Iterator:
    cursor = [node]
    while cursor:
        current = cursor.pop()
        yield current
        cursor.extend(reversed(current.children))


def _is_dynamic(node) -> bool:
    if node is None:
        return False
    if node.type == "template_string":
        return any(c.type == "template_substitution" for c in node.children)
    if node.type == "binary_expression":
        return any(c.type not in {"string", "+"} for c in node.children)
    return node.type in {"identifier", "member_expression", "call_expression", "subscript_expression"}


def _first_arg(call):
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    named = [c for c in args.children if c.is_named and c.type != "comment"]
    return named[0] if named else None


def _string_value(node) -> str | None:
    if node is None or node.type != "string":
        return None
    raw = _text(node)
    return raw[1:-1] if len(raw) >= 2 else ""


class JsAnalyzer:
    def __init__(self, path: str, source: str):
        self.path = path
        self.source = source
        self.lines = source.splitlines()
        self.findings: list[Finding] = []
        self.suppressed = 0
        self._seen: set[tuple[str, int]] = set()

    def add(self, rule_id: str, node, message: str) -> None:
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
            end_line=node.end_point[0] + 1, snippet=self.lines[line - 1].strip() if line - 1 < len(self.lines) else "",
            confidence="MEDIUM", engine="treesitter", remediation=rule.remediation,
        ))

    def run(self) -> None:
        parser = Parser(_JS_LANGUAGE)
        tree = parser.parse(self.source.encode("utf-8"))
        for node in _walk(tree.root_node):
            handler = getattr(self, f"_on_{node.type}", None)
            if handler:
                handler(node)

    # ------------------------------------------------------------ handlers
    def _on_call_expression(self, node) -> None:
        func = node.child_by_field_name("function")
        name = _text(func)
        arg = _first_arg(node)
        if name == "eval":
            self.add("JS001", node, "eval() executa string como código.")
        elif name in {"setTimeout", "setInterval"} and arg is not None and arg.type in {"string", "template_string"}:
            self.add("JS001", node, f"{name}() recebe código em forma de string.")
        elif name in EXEC_FUNCS and _is_dynamic(arg):
            self.add("JS003", node, f"{name}() monta comando com valor dinâmico.")
        elif name in {"document.write", "document.writeln"} and _is_dynamic(arg):
            self.add("JS002", node, f"{name}() com conteúdo dinâmico.")
        elif func is not None and func.type == "member_expression":
            prop = _text(func.child_by_field_name("property"))
            if prop in SQL_METHODS and arg is not None and arg.type in {"template_string", "binary_expression"} \
                    and _is_dynamic(arg) and re.search(r"(?i)\b(select|insert|update|delete)\b", _text(arg)):
                self.add("JS005", node, f".{prop}() recebe SQL montado dinamicamente.")
            elif prop == "insertAdjacentHTML":
                self.add("JS002", node, "insertAdjacentHTML() insere HTML sem sanitização.")

    def _on_new_expression(self, node) -> None:
        if _text(node.child_by_field_name("constructor")) == "Function":
            self.add("JS001", node, "new Function() compila string como código.")

    def _on_assignment_expression(self, node) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None and left.type == "member_expression":
            prop = _text(left.child_by_field_name("property"))
            if prop in {"innerHTML", "outerHTML"} and _is_dynamic(right):
                self.add("JS002", node, f"Atribuição dinâmica a {prop}.")
        name = _text(left).rsplit(".", 1)[-1] if left is not None else ""
        self._check_secret(name, right, node)

    def _on_variable_declarator(self, node) -> None:
        self._check_secret(_text(node.child_by_field_name("name")), node.child_by_field_name("value"), node)

    def _on_pair(self, node) -> None:
        key = _text(node.child_by_field_name("key")).strip("'\"")
        self._check_secret(key, node.child_by_field_name("value"), node)

    def _on_jsx_attribute(self, node) -> None:
        if _text(node).startswith("dangerouslySetInnerHTML"):
            self.add("JS002", node, "dangerouslySetInnerHTML renderiza HTML bruto.")

    def _on_string(self, node) -> None:
        value = _string_value(node) or ""
        if len(value) >= 16:
            for pattern, label in TOKEN_PATTERNS:
                if pattern.search(value):
                    self.add("JS004", node, f"String contém {label}.")
                    return

    def _check_secret(self, name: str, value_node, node) -> None:
        value = _string_value(value_node)
        if value is None or not name:
            return
        if SECRET_NAME_RE.search(name) and not NON_SECRET_NAME_RE.search(name) and looks_like_secret_value(value, name):
            self.add("JS004", node, f"Credencial hardcoded em '{name}'.")


def analyze_javascript(path: str, source: str) -> tuple[list[Finding], int]:
    if not TREE_SITTER_AVAILABLE:
        return [], 0
    analyzer = JsAnalyzer(path, source)
    analyzer.run()
    return analyzer.findings, analyzer.suppressed
