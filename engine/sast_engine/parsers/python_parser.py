"""Parser Python baseado no módulo `ast` da biblioteca padrão.

Além de construir a AST, resolve aliases de import para que as regras trabalhem
com nomes qualificados. Ex.: `from subprocess import Popen as P; P(...)` e
reconhecido como `subprocess.Popen`.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass, field

SUPPRESS_RE = re.compile(r"#\s*(nosec|sast:\s*ignore)\b", re.IGNORECASE)


@dataclass
class ParsedModule:
    path: str
    source: str
    tree: ast.Module
    lines: list[str]
    aliases: dict[str, str] = field(default_factory=dict)
    suppressed_lines: set[int] = field(default_factory=set)

    @property
    def module_name(self) -> str:
        name = self.path.replace("\\", "/").rsplit("/", 1)[-1]
        return name[:-3] if name.endswith(".py") else name

    def snippet(self, line: int, end_line: int | None = None) -> str:
        end = end_line or line
        end = min(end, line + 4)  # limita snippets muito grandes
        return "\n".join(self.lines[line - 1:end]).rstrip()

    def context(self, line: int, radius: int = 6) -> str:
        start = max(1, line - radius)
        end = min(len(self.lines), line + radius)
        out = []
        for n in range(start, end + 1):
            marker = ">>" if n == line else "  "
            out.append(f"{marker}{n:4d} | {self.lines[n - 1]}")
        return "\n".join(out)

    def is_suppressed(self, line: int) -> bool:
        return line in self.suppressed_lines

    # ------------------------------------------------------------ resolucao de nomes
    def qualname(self, node: ast.AST) -> str | None:
        """Nome qualificado de uma expressão `a.b.c`, resolvendo aliases de import."""
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.qualname(node.value)
            if base is None:
                return None
            return f"{base}.{node.attr}"
        if isinstance(node, ast.Call):
            # ex.: request.args.get(...).strip -> "request.args.get().strip"
            base = self.qualname(node.func)
            return f"{base}()" if base else None
        if isinstance(node, ast.Subscript):
            base = self.qualname(node.value)
            return f"{base}[]" if base else None
        return None


def _collect_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    aliases.setdefault(top, top)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def _suppressed_lines(source: str) -> set[int]:
    lines: set[int] = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT and SUPPRESS_RE.search(tok.string):
                lines.add(tok.start[0])
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return lines


def parse_python(path: str, source: str) -> ParsedModule:
    """Faz o parse do arquivo. Levanta SyntaxError se o código for inválido."""
    tree = ast.parse(source, filename=path, type_comments=False)
    return ParsedModule(
        path=path,
        source=source,
        tree=tree,
        lines=source.splitlines(),
        aliases=_collect_aliases(tree),
        suppressed_lines=_suppressed_lines(source),
    )
