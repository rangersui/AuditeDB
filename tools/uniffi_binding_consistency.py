#!/usr/bin/env python3
"""Fail when a tracked UniFFI Python binding differs from fresh output."""

from __future__ import annotations

import argparse
import difflib
import io
from pathlib import Path
import tokenize


Token = tuple[int, str]


def token_value(token: tokenize.TokenInfo) -> str:
    if token.type == tokenize.COMMENT:
        return token.string.rstrip(" \t\f")
    if token.type in {tokenize.NEWLINE, tokenize.NL}:
        return "\n"
    return token.string


def binding_tokens(path: Path) -> list[Token]:
    source = path.read_text(encoding="utf-8")
    try:
        compile(source, str(path), "exec")
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        return [(token.type, token_value(token)) for token in tokens]
    except (SyntaxError, tokenize.TokenError) as error:
        raise ValueError(f"{path} is not valid Python: {error}") from error


def render_tokens(tokens: list[Token]) -> list[str]:
    return [f"{tokenize.tok_name[token_type]} {value!r}" for token_type, value in tokens]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tracked", type=Path)
    parser.add_argument("generated", type=Path)
    args = parser.parse_args(argv)

    try:
        tracked = binding_tokens(args.tracked)
        generated = binding_tokens(args.generated)
    except ValueError as error:
        print(error)
        return 1
    if tracked == generated:
        print("UniFFI Python binding is current")
        return 0

    print("tracked UniFFI Python binding is stale; regenerate it")
    print(
        "\n".join(
            difflib.unified_diff(
                render_tokens(tracked),
                render_tokens(generated),
                fromfile=str(args.tracked),
                tofile=str(args.generated),
                lineterm="",
            )
        )
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
