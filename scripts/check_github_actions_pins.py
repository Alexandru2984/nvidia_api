#!/usr/bin/env python3
"""Reject remote GitHub Actions that are not pinned to a full commit SHA."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


USES_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
FULL_COMMIT = re.compile(r"[0-9a-f]{40}")


def unpinned_actions(workflow_root: Path) -> list[str]:
    findings: list[str] = []
    workflows = sorted(
        path
        for suffix in ("*.yml", "*.yaml")
        for path in workflow_root.rglob(suffix)
    )

    if not workflows:
        return [f"{workflow_root}: no workflow files found"]

    for workflow in workflows:
        for line_number, line in enumerate(
            workflow.read_text(encoding="utf-8").splitlines(), start=1
        ):
            match = USES_LINE.match(line)
            if not match:
                continue
            action = match.group(1).strip("'\"")
            if action.startswith(("./", "docker://")):
                continue
            if "@" not in action:
                findings.append(
                    f"{workflow}:{line_number}: remote action has no ref: {action}"
                )
                continue
            ref = action.rsplit("@", maxsplit=1)[1]
            if not FULL_COMMIT.fullmatch(ref):
                findings.append(
                    f"{workflow}:{line_number}: remote action is not pinned to a "
                    f"full lowercase commit SHA: {action}"
                )

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "workflow_root",
        nargs="?",
        type=Path,
        default=Path(".github/workflows"),
    )
    args = parser.parse_args()

    findings = unpinned_actions(args.workflow_root)
    if findings:
        print("\n".join(findings))
        return 1

    print(f"validated immutable GitHub Actions in {args.workflow_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
