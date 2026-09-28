"""Fix suggestion generator.

Takes a finding dict (with AST metadata from source_tracer) and produces a
suggested replacement code line.  Returns None for log-only findings that
have no source context.
"""
from __future__ import annotations

# Map PII field names to the appropriate masking function
_FIELD_TO_MASK_FN = {
    "ic_number": "mask_ic",
    "ic": "mask_ic",
    "card_number": "mask_card",
    "card": "mask_card",
    "email": "mask_email",
    "account_number": "mask_account_number",
    "phone": "mask_phone",
}


def suggest_fix(match: dict) -> str | None:
    """Return a suggested safe replacement for the logged line in *match*.

    Returns ``None`` when there is not enough source context to generate a
    suggestion (e.g. log-only findings with no ``source_file``).
    """
    source_file = match.get("source_file")
    source_line = match.get("source_line")
    snippet = match.get("snippet") or ""
    pii_fields: list[str] = match.get("pii_fields") or []
    logs_whole_object: bool = match.get("logs_whole_object", False)

    if not source_file or not source_line or not snippet:
        return None

    # ------------------------------------------------------------------
    # Whole-object logging: suggest logging only the id
    # ------------------------------------------------------------------
    if logs_whole_object:
        # Detect the variable name from the snippet or variables list
        variables: list[str] = match.get("variables") or []
        # Pick the first non-PII-field variable (likely the object name)
        obj_name = next(
            (v for v in variables if v not in _FIELD_TO_MASK_FN and len(v) > 1),
            "obj",
        )
        method = match.get("logger_method") or "info"
        if method == "print":
            return f'print("Processing {obj_name}_id=%s", {obj_name}.id)'
        return (
            f'logger.{method}("Processing {obj_name}_id=%s", {obj_name}.id)'
        )

    # ------------------------------------------------------------------
    # Direct PII field reference: wrap in mask_*()
    # ------------------------------------------------------------------
    if pii_fields:
        result = snippet
        for field in pii_fields:
            mask_fn = _FIELD_TO_MASK_FN.get(field)
            if mask_fn is None:
                continue
            # Replace `obj.field` with `mask_fn(obj.field)` in the snippet.
            # We do a simple string replacement; if the snippet has the pattern
            # already wrapped we skip it.
            pattern = f".{field}"
            if pattern in result and f"{mask_fn}(" not in result:
                result = result.replace(
                    pattern,
                    f".{field}",   # keep original attr access
                )
                # Actually wrap the whole attribute expression
                import re
                result = re.sub(
                    rf"(\w+\.{re.escape(field)})",
                    rf"{mask_fn}(\1)",
                    result,
                )
        return result

    # No actionable pattern found
    return None
