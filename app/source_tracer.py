"""AST-based source analyser and source-to-log correlator."""
from __future__ import annotations

import ast
from pathlib import Path

# ---------------------------------------------------------------------------
# Known PII field names
# ---------------------------------------------------------------------------

_PII_FIELDS = frozenset(
    {"ic_number", "card_number", "email", "account_number", "phone", "card", "ic"}
)

_LOG_METHODS = frozenset(
    {"info", "debug", "warning", "error", "exception"}
)

# Variable names that are dangerous to log regardless of type annotations
_DANGEROUS_VARS = frozenset(
    {"payload", "request_data", "request", "error", "exc", "exception",
     "customer", "user", "account", "card", "token", "secret", "password"}
)


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------

class _LogCallVisitor(ast.NodeVisitor):
    """Walk an AST and collect every logger.* / print() call."""

    def __init__(self, source_lines: list[str], rel_path: str) -> None:
        self._lines = source_lines
        self._rel_path = rel_path
        self.findings: list[dict] = []

    # ------------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        method = self._extract_logger_method(node.func)
        if method is not None:
            self._record(node, method)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    def _extract_logger_method(self, func_node: ast.expr) -> str | None:
        """Return the logging method name if this is a logger.* or print() call."""
        if isinstance(func_node, ast.Attribute):
            if func_node.attr in _LOG_METHODS:
                return func_node.attr
        elif isinstance(func_node, ast.Name):
            if func_node.id == "print":
                return "print"
        return None

    # ------------------------------------------------------------------
    def _record(self, call_node: ast.Call, method: str) -> None:
        variables: list[str] = []
        pii_fields: list[str] = []
        logs_whole_object = False

        for arg in call_node.args:
            self._extract_names(arg, variables, pii_fields)
            # A plain ast.Name in an f-string slot means a whole object is logged.
            if self._is_whole_object_arg(arg):
                logs_whole_object = True
            # A plain Name passed directly as a logger arg (e.g. logger.exception(error))
            # is also a whole-object / dangerous-variable pattern.
            if isinstance(arg, ast.Name) and arg.id in _DANGEROUS_VARS:
                logs_whole_object = True

        # Also check keyword argument values
        for kw in call_node.keywords:
            if kw.value is not None:
                self._extract_names(kw.value, variables, pii_fields)
                if isinstance(kw.value, ast.Name) and kw.value.id in _DANGEROUS_VARS:
                    logs_whole_object = True

        # Also flag when a dangerous variable name appears in any arg position
        # (covers logger.debug("msg: %s", request_data) — request_data is arg[1])
        for var in variables:
            if var in _DANGEROUS_VARS:
                logs_whole_object = True
                break

        # Only record calls that look risky
        if not pii_fields and not logs_whole_object:
            return

        lineno = call_node.lineno
        snippet = self._lines[lineno - 1].rstrip() if lineno <= len(self._lines) else ""
        severity = "HIGH" if (pii_fields or logs_whole_object) else "MEDIUM"

        self.findings.append(
            {
                "source_file": self._rel_path,
                "source_line": lineno,
                "logger_method": method,
                "variables": list(dict.fromkeys(variables)),   # unique, ordered
                "pii_fields": list(dict.fromkeys(pii_fields)),
                "logs_whole_object": logs_whole_object,
                "snippet": snippet.strip(),
                "pii_type": "SOURCE_LEAK",
                "severity": severity,
                "value": snippet.strip(),
                "log_file": None,
                "log_line": None,
            }
        )

    # ------------------------------------------------------------------
    def _extract_names(
        self,
        node: ast.expr,
        variables: list[str],
        pii_fields: list[str],
    ) -> None:
        """Recursively pull Name and Attribute nodes from *node*."""
        if isinstance(node, ast.Attribute):
            variables.append(node.attr)
            if node.attr in _PII_FIELDS:
                pii_fields.append(node.attr)
            self._extract_names(node.value, variables, pii_fields)
        elif isinstance(node, ast.Name):
            variables.append(node.id)
        elif isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    self._extract_names(value.value, variables, pii_fields)
        elif isinstance(node, (ast.BinOp, ast.IfExp)):
            for child in ast.iter_child_nodes(node):
                self._extract_names(child, variables, pii_fields)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    def _is_whole_object_arg(self, arg: ast.expr) -> bool:
        """Return True when *arg* is or contains a bare Name in an f-string slot."""
        if isinstance(arg, ast.JoinedStr):
            for value in arg.values:
                if isinstance(value, ast.FormattedValue):
                    if isinstance(value.value, ast.Name):
                        return True
        return False


# ---------------------------------------------------------------------------
# Public scanner function
# ---------------------------------------------------------------------------

def scan_source_files_ast(path: str) -> list[dict]:
    """Walk every .py file under *path* and return one finding dict per risky log call."""
    results: list[dict] = []
    root = Path(path)
    for py_file in sorted(root.rglob("*.py")):
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue
        lines = source.splitlines()
        visitor = _LogCallVisitor(lines, str(py_file))
        visitor.visit(tree)
        results.extend(visitor.findings)
    return results


# ---------------------------------------------------------------------------
# Source-to-log correlator
# ---------------------------------------------------------------------------

def correlate(log_findings: list[dict], source_findings: list[dict]) -> list[dict]:
    """Link log findings to the source statement that produced them (best-effort).

    For each log finding the correlator checks whether any source finding's
    *snippet* text (normalised) contains a substring that also appears in the
    log line, or vice-versa.  When matched, ``source_file``, ``source_line``,
    and ``logger_method`` are copied into the log finding.

    Returns all findings (log + source) sorted HIGH-first.
    """
    merged = []

    for log_f in log_findings:
        log_line = (log_f.get("snippet") or log_f.get("value") or "").lower()
        for src_f in source_findings:
            snippet = (src_f.get("snippet") or "").lower()
            # Extract the literal/template text from the snippet so we can
            # look for it inside the log output.
            # Heuristic: any bare word ≥4 chars that is not a Python keyword
            # appearing in both is treated as a match.
            if _snippets_correlate(snippet, log_line):
                log_f = dict(log_f)   # shallow copy before mutating
                log_f["source_file"] = src_f["source_file"]
                log_f["source_line"] = src_f["source_line"]
                log_f["logger_method"] = src_f.get("logger_method")
                break
        merged.append(log_f)

    # Add source findings that have no corresponding log finding
    merged.extend(source_findings)

    # Sort: HIGH before MEDIUM before LOW
    _sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    merged.sort(key=lambda x: _sev_order.get(x.get("severity", "LOW"), 99))
    return merged


# ---------------------------------------------------------------------------
# Correlation helper
# ---------------------------------------------------------------------------

_STOP_WORDS = frozenset(
    {"logger", "info", "debug", "warning", "error", "exception",
     "print", "self", "true", "false", "none", "def", "return",
     "import", "from", "class", "raise", "try", "except"}
)


def _snippets_correlate(snippet: str, log_line: str) -> bool:
    """Return True when snippet and log_line share a meaningful token."""
    import re as _re
    tokens = {
        t for t in _re.findall(r"[a-z_][a-z0-9_]{3,}", snippet)
        if t not in _STOP_WORDS
    }
    for token in tokens:
        if token in log_line:
            return True
    return False
