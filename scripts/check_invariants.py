#!/usr/bin/env python3
"""LocalEDR repository wrapper for the global Gemini Decision 1 invariant gate.

Resolves the global ``check_invariants_decision1.py`` CLI, applies LocalEDR's
default path whitelist (excluding large generated schemas, HTML artifacts, and
integration tests unless ``--include-tests`` is passed), and forwards options
with UTF-8 environment guards enabled.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import os
from pathlib import Path
import subprocess
import sys

DEFAULT_PATHS: tuple[str, ...] = (
    "crates/*/src/**",
    "apps/ledr-ui/src/**",
    "apps/ledr-ui/ui/**",
    "extensions/**",
    "rules/**",
)

TEST_PATHS: tuple[str, ...] = (
    "crates/*/tests/**",
)

GATE_SCRIPT_ENV = "LEDR_INVARIANT_GATE_SCRIPT"
DEFAULT_GATE_SCRIPT_REL = (
    Path(".gemini")
    / "config"
    / "plugins"
    / "shared-skills"
    / "skills"
    / "invariant-gate"
    / "scripts"
    / "check_invariants_decision1.py"
)


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser for the LocalEDR invariant gate wrapper."""
    parser = argparse.ArgumentParser(
        description=(
            "Run LocalEDR's Gemini Decision 1 invariant gate with safe default "
            "path filtering."
        )
    )
    parser.add_argument(
        "--gate-script",
        help="Override path to global check_invariants_decision1.py.",
    )
    parser.add_argument(
        "--base",
        default=None,
        help="Base git ref for <ref>...HEAD diff (defaults to 'main' unless --staged or --diff-file is given).",
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Inspect staged changes (--cached) instead of comparing against --base.",
    )
    parser.add_argument(
        "--diff-file",
        help="Read unified diff from a file instead of invoking git diff.",
    )
    parser.add_argument(
        "--include-tests",
        action="store_true",
        help="Include integration test paths (crates/*/tests/**) in --paths.",
    )
    parser.add_argument(
        "--paths",
        nargs="+",
        help="Override DEFAULT_PATHS with explicit path patterns.",
    )
    parser.add_argument(
        "--no-systems-preset",
        action="store_true",
        help="Omit '--preset systems-pre-pr' when invoking the global gate.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as exit code 1 and zero rules as exit code 2.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate payload and print extracted rules without calling the API.",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        help="Output format passed to the global invariant gate.",
    )
    parser.add_argument(
        "--max-chars",
        type=int,
        help="Maximum input character count passed to the global invariant gate.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        help="HTTP timeout in seconds passed to the global invariant gate.",
    )
    return parser


def resolve_gate_script(
    gate_script: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> Path:
    """Resolve the global invariant gate script path or raise FileNotFoundError.

    Resolution priority:
    1. ``gate_script`` argument (``--gate-script``)
    2. ``LEDR_INVARIANT_GATE_SCRIPT`` environment variable
    3. ``Path.home() / ".gemini/config/plugins/shared-skills/skills/invariant-gate/scripts/check_invariants_decision1.py"``
    """
    env_map = os.environ if env is None else env

    if gate_script is not None:
        raw = str(gate_script).strip()
        if not raw:
            raise FileNotFoundError("Gate script path passed via --gate-script is empty.")
        candidate = Path(raw).expanduser()
    else:
        env_override = env_map.get(GATE_SCRIPT_ENV, "").strip()
        if env_override:
            candidate = Path(env_override).expanduser()
        else:
            candidate = Path.home() / DEFAULT_GATE_SCRIPT_REL

    if not candidate.is_file():
        raise FileNotFoundError(
            f"Invariant gate script not found or not a file: {candidate}"
        )
    return candidate.resolve()


def _resolve_effective_paths(
    paths: Sequence[str] | None,
    include_tests: bool,
) -> list[str]:
    base_paths = list(paths) if paths else list(DEFAULT_PATHS)
    if include_tests:
        base_paths.extend(TEST_PATHS)
    return list(dict.fromkeys(base_paths))


def build_gate_command(
    args: argparse.Namespace,
    gate_script: Path | str,
    python_executable: str | None = None,
) -> list[str]:
    """Build the subprocess command list for ``check_invariants_decision1.py``."""
    exe = python_executable or sys.executable
    cmd: list[str] = [exe, str(gate_script)]

    if args.base is not None:
        if args.base:
            cmd.extend(["--base", args.base])
    elif not args.staged and not args.diff_file:
        cmd.extend(["--base", "main"])

    if args.staged:
        cmd.append("--staged")
    if args.diff_file:
        cmd.extend(["--diff-file", args.diff_file])

    if not args.no_systems_preset:
        cmd.extend(["--preset", "systems-pre-pr"])

    effective_paths = _resolve_effective_paths(args.paths, args.include_tests)
    if effective_paths:
        cmd.append("--paths")
        cmd.extend(effective_paths)

    if args.strict:
        cmd.append("--strict")
    if args.dry_run:
        cmd.append("--dry-run")
    if args.format is not None:
        cmd.extend(["--format", args.format])
    if args.max_chars is not None:
        cmd.extend(["--max-chars", str(args.max_chars)])
    if args.timeout is not None:
        cmd.extend(["--timeout", str(args.timeout)])

    return cmd


def main(
    argv: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> int:
    """Parse arguments, resolve the global gate script, and run it safely."""
    parser = build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        gate_script = resolve_gate_script(args.gate_script, env=env)
    except (FileNotFoundError, OSError, ValueError) as exc:
        print(f"ERROR [gate_script_not_found]: {exc}", file=sys.stderr)
        return 2

    cmd = build_gate_command(args, gate_script)
    child_env = dict(os.environ if env is None else env)
    child_env["PYTHONUTF8"] = "1"
    child_env["PYTHONIOENCODING"] = "utf-8"

    try:
        proc = subprocess.run(cmd, env=child_env, check=False)
    except OSError as exc:
        print(f"ERROR [gate_exec_failed]: {exc}", file=sys.stderr)
        return 2

    return int(proc.returncode)


if __name__ == "__main__":
    sys.exit(main())
