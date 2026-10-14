#!/usr/bin/env python3
"""Verify that the production wheel lock exactly mirrors runtime requirements."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

REQUIREMENT_RE = re.compile(r'^([A-Za-z0-9._-]+)==([^\s]+)$')
LOCK_RE = re.compile(
    r'^([A-Za-z0-9._-]+)==([^\s]+) --hash=sha256:([0-9a-f]{64})$',
)


def canonicalize(name: str) -> str:
    return re.sub(r'[-_.]+', '-', name).lower()


def parse_file(path: Path, pattern: re.Pattern[str], label: str) -> dict[str, tuple[str, str]]:
    parsed: dict[str, tuple[str, str]] = {}
    for number, raw in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        match = pattern.fullmatch(line)
        if not match:
            raise ValueError(f'{path}:{number}: invalid {label} entry')
        display_name, version = match.group(1), match.group(2)
        name = canonicalize(display_name)
        if name in parsed:
            raise ValueError(f'{path}:{number}: duplicate package {display_name}')
        parsed[name] = (display_name, version)
    if not parsed:
        raise ValueError(f'{path}: no {label} entries')
    return parsed


def validate(requirements_path: Path, lock_path: Path) -> int:
    requirements = parse_file(requirements_path, REQUIREMENT_RE, 'requirement')
    locked = parse_file(lock_path, LOCK_RE, 'locked requirement')
    if requirements != locked:
        missing = sorted(set(requirements) - set(locked))
        extra = sorted(set(locked) - set(requirements))
        changed = sorted(
            name for name in set(requirements) & set(locked)
            if requirements[name] != locked[name]
        )
        raise ValueError(
            f'lock mismatch: missing={missing}, extra={extra}, changed={changed}',
        )
    return len(requirements)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('requirements', nargs='?', default='backend/requirements.txt')
    parser.add_argument('lock', nargs='?', default='backend/requirements.lock')
    args = parser.parse_args()
    try:
        count = validate(Path(args.requirements), Path(args.lock))
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    print(f'validated {count} hash-locked runtime requirements')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
