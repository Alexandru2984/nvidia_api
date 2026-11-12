#!/usr/bin/env python3
"""Stage and validate privacy-safe incident controls in a runtime dotenv."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


MAX_ENV_BYTES = 128 * 1024
CONTROL_PATTERN = re.compile(
    r"^[ \t]*(?:export[ \t]+)?"
    r"(?P<key>AI_GENERATION_ENABLED|REGISTRATION_MODE)[ \t]*=.*$"
)
ALLOWED_GENERATION = frozenset({"enabled", "disabled"})
ALLOWED_REGISTRATION = frozenset({"open", "invite", "closed"})


class IncidentControlError(ValueError):
    """Raised when the runtime configuration cannot be changed safely."""


@dataclass(frozen=True)
class Controls:
    generation: str
    registration: str

    def environment_values(self) -> dict[str, str]:
        return {
            "AI_GENERATION_ENABLED": "true" if self.generation == "enabled" else "false",
            "REGISTRATION_MODE": self.registration,
        }


def _read_regular_file(path: Path) -> str:
    try:
        before = path.lstat()
    except OSError as exc:
        raise IncidentControlError("runtime configuration is unavailable") from exc
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise IncidentControlError("runtime configuration has an unsafe type")
    if not 1 <= before.st_size <= MAX_ENV_BYTES:
        raise IncidentControlError("runtime configuration has an unsafe size")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise IncidentControlError("runtime configuration cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise IncidentControlError("runtime configuration changed during validation")
        payload = bytearray()
        while len(payload) <= MAX_ENV_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_ENV_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_ENV_BYTES:
        raise IncidentControlError("runtime configuration has an unsafe size")
    try:
        text = bytes(payload).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IncidentControlError("runtime configuration is not valid UTF-8") from exc
    text = text.replace("\r\n", "\n")
    if "\r" in text or any(ord(character) < 32 and character not in "\n\t" for character in text):
        raise IncidentControlError("runtime configuration contains control bytes")
    return text


def _unquote_control(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    if not re.fullmatch(r"[A-Za-z]+", value):
        raise IncidentControlError("incident control value is malformed")
    return value.lower()


def parse_controls(text: str) -> Controls:
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = CONTROL_PATTERN.fullmatch(line)
        if match is None:
            continue
        key = match.group("key")
        if key in values:
            raise IncidentControlError("runtime configuration has a duplicate incident control")
        raw = line.split("=", 1)[1]
        values[key] = _unquote_control(raw)

    generation_raw = values.get("AI_GENERATION_ENABLED", "true")
    if generation_raw not in {"true", "false"}:
        raise IncidentControlError("generation incident control is invalid")
    registration = values.get("REGISTRATION_MODE", "open")
    if registration not in ALLOWED_REGISTRATION:
        raise IncidentControlError("registration incident control is invalid")
    return Controls(
        generation="enabled" if generation_raw == "true" else "disabled",
        registration=registration,
    )


def render_controls(text: str, desired: Controls) -> str:
    replacements = desired.environment_values()
    found: set[str] = set()
    output: list[str] = []
    for line in text.splitlines():
        match = CONTROL_PATTERN.fullmatch(line)
        if match is None:
            output.append(line)
            continue
        key = match.group("key")
        if key in found:
            raise IncidentControlError("runtime configuration has a duplicate incident control")
        found.add(key)
        output.append(f"{key}={replacements[key]}")
    for key in ("AI_GENERATION_ENABLED", "REGISTRATION_MODE"):
        if key not in found:
            output.append(f"{key}={replacements[key]}")
    return "\n".join(output).rstrip("\n") + "\n"


def write_exclusive(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise IncidentControlError("staged runtime configuration cannot be created") from exc
    try:
        encoded = content.encode("utf-8")
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def desired_controls(args: argparse.Namespace) -> Controls:
    if args.generation not in ALLOWED_GENERATION:
        raise IncidentControlError("generation incident control is invalid")
    if args.registration not in ALLOWED_REGISTRATION:
        raise IncidentControlError("registration incident control is invalid")
    return Controls(args.generation, args.registration)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", required=True, type=Path)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--show0", action="store_true")
    action.add_argument("--stage-output", type=Path)
    action.add_argument("--check", action="store_true")
    parser.add_argument("--generation", choices=sorted(ALLOWED_GENERATION))
    parser.add_argument("--registration", choices=sorted(ALLOWED_REGISTRATION))
    args = parser.parse_args()

    try:
        text = _read_regular_file(args.env_file)
        current = parse_controls(text)
        if args.show0:
            if args.generation is not None or args.registration is not None:
                raise IncidentControlError("show mode does not accept desired controls")
            sys.stdout.buffer.write(
                current.generation.encode("ascii") + b"\0"
                + current.registration.encode("ascii") + b"\0"
            )
            return 0

        if args.generation is None or args.registration is None:
            raise IncidentControlError("both desired incident controls are required")
        desired = desired_controls(args)
        if args.check:
            if current != desired:
                raise IncidentControlError("runtime incident controls do not match")
            print(
                f"Incident controls are valid: generation={current.generation} "
                f"registration={current.registration}"
            )
            return 0

        rendered = render_controls(text, desired)
        parse_controls(rendered)
        write_exclusive(args.stage_output, rendered)
        print(
            f"Staged incident controls: generation={desired.generation} "
            f"registration={desired.registration}"
        )
        return 0
    except (IncidentControlError, OSError) as exc:
        print(f"Incident control validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
