#!/usr/bin/env python3
"""Fail when a tracked UniFFI Python binding differs from fresh output."""

from __future__ import annotations

import argparse
import difflib
from pathlib import Path


def canonical_lines(path: Path) -> list[str]:
    return [line.rstrip() for line in path.read_text(encoding="utf-8").splitlines()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tracked", type=Path)
    parser.add_argument("generated", type=Path)
    args = parser.parse_args()

    tracked = canonical_lines(args.tracked)
    generated = canonical_lines(args.generated)
    if tracked == generated:
        print("UniFFI Python binding is current")
        return 0

    print("tracked UniFFI Python binding is stale; regenerate it")
    print(
        "\n".join(
            difflib.unified_diff(
                tracked,
                generated,
                fromfile=str(args.tracked),
                tofile=str(args.generated),
                lineterm="",
            )
        )
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
