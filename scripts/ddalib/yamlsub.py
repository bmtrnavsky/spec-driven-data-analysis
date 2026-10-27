"""Strict YAML-subset parser (stdlib only).

`dda` must run without third-party packages, and `config.yaml` is
human-owned, so the parser is deliberately small and fails closed: any
construct it does not understand raises `YamlSubsetError` instead of
guessing.

Supported:
  - block mappings (`key: value`, `key:` + indented block)
  - block sequences (`- scalar`, `- key: value` mapping items)
  - scalars: null/~, true/false, ints, floats, single/double quoted strings,
    plain strings
  - flow sequences of scalars on one line: `[a, "b", 3]`, and `{}` / `[]`
  - `#` comments (outside quotes)

Rejected: tabs in indentation, anchors/aliases/tags, block scalars (| >),
flow mappings with content, multi-document streams, duplicate keys.
"""
from __future__ import annotations

import re

__all__ = ["YamlSubsetError", "loads", "load_file"]


class YamlSubsetError(ValueError):
    pass


_KEY_RE = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_\-\.]*)\s*:(?:\s+(.*))?$")
_INT_RE = re.compile(r"^[-+]?[0-9]+$")
_FLOAT_RE = re.compile(r"^[-+]?([0-9]+\.[0-9]*|\.[0-9]+)([eE][-+]?[0-9]+)?$")


def _strip_comment(line: str, lineno: int) -> str:
    out = []
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            out.append(ch)
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        else:
            out.append(ch)
        i += 1
    if quote:
        raise YamlSubsetError(f"line {lineno}: unterminated quoted string")
    return "".join(out).rstrip()


def _scalar(text: str, lineno: int):
    t = text.strip()
    if t == "" or t in ("~", "null", "Null", "NULL"):
        return None
    if t[0] in "&*!|>":
        raise YamlSubsetError(f"line {lineno}: unsupported YAML construct {t[0]!r}")
    if t in ("true", "True", "TRUE"):
        return True
    if t in ("false", "False", "FALSE"):
        return False
    if t == "[]":
        return []
    if t == "{}":
        return {}
    if t[0] == "{":
        raise YamlSubsetError(f"line {lineno}: flow mappings are not supported")
    if t[0] == "[":
        if t[-1] != "]":
            raise YamlSubsetError(f"line {lineno}: unterminated flow sequence")
        return [_scalar(p, lineno) for p in _split_flow(t[1:-1], lineno)]
    if t[0] == '"':
        if len(t) < 2 or t[-1] != '"':
            raise YamlSubsetError(f"line {lineno}: bad double-quoted string")
        body = t[1:-1]
        try:
            import json
            return json.loads('"' + body + '"')
        except ValueError as exc:
            raise YamlSubsetError(f"line {lineno}: bad escape in string: {exc}") from None
    if t[0] == "'":
        if len(t) < 2 or t[-1] != "'":
            raise YamlSubsetError(f"line {lineno}: bad single-quoted string")
        return t[1:-1].replace("''", "'")
    if _INT_RE.match(t):
        return int(t)
    if _FLOAT_RE.match(t):
        return float(t)
    if ": " in t or t.endswith(":"):
        raise YamlSubsetError(f"line {lineno}: ambiguous plain scalar {t!r}; quote it")
    return t


def _split_flow(inner: str, lineno: int) -> list[str]:
    parts, buf, quote = [], [], None
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch in "[]{}":
            raise YamlSubsetError(f"line {lineno}: nested flow collections are not supported")
        elif ch == ",":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf)
    if tail.strip() or parts:
        parts.append(tail)
    parts = [p for p in parts]
    if any(not p.strip() for p in parts):
        raise YamlSubsetError(f"line {lineno}: empty element in flow sequence")
    return parts


def _lines(text: str):
    out = []
    for n, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        if raw.strip() in ("---", "...") and n == 1:
            continue
        if raw.strip() in ("---", "..."):
            raise YamlSubsetError(f"line {n}: multi-document streams are not supported")
        body = _strip_comment(raw, n)
        if not body.strip():
            continue
        indent_str = body[: len(body) - len(body.lstrip(" \t"))]
        if "\t" in indent_str:
            raise YamlSubsetError(f"line {n}: tab in indentation")
        out.append((n, len(indent_str), body.strip()))
    return out


def loads(text: str):
    lines = _lines(text)
    if not lines:
        return {}
    value, pos = _parse_block(lines, 0, lines[0][1])
    if pos != len(lines):
        n = lines[pos][0]
        raise YamlSubsetError(f"line {n}: unexpected indentation")
    return value


def _parse_block(lines, pos, indent):
    if lines[pos][2].startswith("- ") or lines[pos][2] == "-":
        return _parse_seq(lines, pos, indent)
    return _parse_map(lines, pos, indent)


def _parse_map(lines, pos, indent, first_inline=None):
    result: dict = {}
    while pos < len(lines):
        n, ind, body = lines[pos]
        if ind < indent:
            break
        if ind > indent:
            raise YamlSubsetError(f"line {n}: unexpected indentation")
        if body.startswith("- ") or body == "-":
            raise YamlSubsetError(f"line {n}: sequence item where a mapping key was expected")
        m = _KEY_RE.match(body)
        if not m:
            raise YamlSubsetError(f"line {n}: expected 'key: value', got {body!r}")
        key, rest = m.group(1), m.group(2)
        if key in result:
            raise YamlSubsetError(f"line {n}: duplicate key {key!r}")
        pos += 1
        if rest is None or rest == "":
            if pos < len(lines) and lines[pos][1] > indent:
                result[key], pos = _parse_block(lines, pos, lines[pos][1])
            elif pos < len(lines) and lines[pos][1] == indent and (
                lines[pos][2].startswith("- ") or lines[pos][2] == "-"
            ):
                # YAML allows a sequence at the same indent as its parent key.
                result[key], pos = _parse_seq(lines, pos, indent)
            else:
                result[key] = None
        else:
            result[key] = _scalar(rest, n)
    return result, pos


def _parse_seq(lines, pos, indent):
    result: list = []
    while pos < len(lines):
        n, ind, body = lines[pos]
        if ind < indent:
            break
        if ind > indent:
            raise YamlSubsetError(f"line {n}: unexpected indentation")
        if not (body.startswith("- ") or body == "-"):
            break
        item = body[1:].strip()
        pos += 1
        if item == "":
            if pos < len(lines) and lines[pos][1] > indent:
                val, pos = _parse_block(lines, pos, lines[pos][1])
                result.append(val)
            else:
                result.append(None)
            continue
        if _KEY_RE.match(item) and not item.startswith(("'", '"')):
            # Mapping item: "- key: v" followed by keys indented to the item column.
            item_indent = ind + (len(body) - len(item))
            sub = [(n, item_indent, item)]
            j = pos
            while j < len(lines) and lines[j][1] >= item_indent:
                sub.append(lines[j])
                j += 1
            val, used = _parse_map(sub, 0, item_indent)
            if used != len(sub):
                raise YamlSubsetError(f"line {sub[used][0]}: unexpected indentation")
            result.append(val)
            pos = j
        else:
            result.append(_scalar(item, n))
    return result, pos


def load_file(path) -> object:
    with open(path, "r", encoding="utf-8") as fh:
        return loads(fh.read())
