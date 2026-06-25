#!/usr/bin/env python3
"""Reject CR bytes and fixture filename case collisions in committed goldens."""

from __future__ import annotations

import json
from pathlib import Path


CHECK_SUFFIXES = {".json", ".jsonl", ".toml"}
SKIP_DIRS = {".git", "target", ".beads"}
FIXTURE_PARTS = {"fixtures", "golden"}


def emit(event: str, **fields: object) -> None:
    payload = {"gate": "golden-lf", "event": event}
    payload.update(fields)
    print(json.dumps(payload, sort_keys=True))


def should_check(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return False
    return path.suffix in CHECK_SUFFIXES or ".golden" in path.name


def is_fixture_path(path: Path) -> bool:
    return any(part in FIXTURE_PARTS for part in path.parts)


def checked_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file() and should_check(path))


def main() -> int:
    root = Path.cwd()
    violations: list[dict[str, object]] = []
    fixture_keys: dict[str, Path] = {}
    collisions: list[dict[str, str]] = []
    uppercase_fixtures: list[str] = []

    files = checked_files(root)
    for path in files:
        rel = path.relative_to(root)
        data = path.read_bytes()
        if b"\r" in data:
            violations.append({"path": str(rel), "byte_offset": data.index(b"\r")})

        if is_fixture_path(rel):
            lowered = str(rel).lower()
            if str(rel) != lowered:
                uppercase_fixtures.append(str(rel))
            previous = fixture_keys.get(lowered)
            if previous is not None and previous != rel:
                collisions.append({"first": str(previous), "second": str(rel)})
            else:
                fixture_keys[lowered] = rel

    emit(
        "verdict",
        files_checked=len(files),
        crlf_violations=violations,
        uppercase_fixtures=uppercase_fixtures,
        fixture_case_collisions=collisions,
    )

    if violations or uppercase_fixtures or collisions:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
