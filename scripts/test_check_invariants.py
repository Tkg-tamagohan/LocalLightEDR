#!/usr/bin/env python3
"""Specification tests for LocalEDR invariant gate config and wrapper (T1-01..T1-06).

All tests run offline without GEMINI_API_KEY.
"""

from __future__ import annotations

from contextlib import redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import check_invariants  # noqa: E402

QUESTION_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

EXPECTED_QUESTIONS: dict[str, tuple[list[str], float, float]] = {
    "proto_frozen_api_compat": (
        ["crates/ledr-proto/**"],
        0.60,
        0.35,
    ),
    "two_lane_no_unbounded_channel": (
        ["crates/ledr-daemon/src/**", "crates/ledr-sensor-win/src/**"],
        0.65,
        0.40,
    ),
    "never_suspend_and_create_time": (
        ["crates/ledr-sensor-win/src/defense/**", "crates/ledr-daemon/src/**"],
        0.65,
        0.40,
    ),
    "canary_write_only_and_expired_suspended": (
        ["crates/ledr-sensor-win/src/etw/file_canary/**", "crates/ledr-daemon/src/engine/**"],
        0.65,
        0.40,
    ),
    "session0_non_system_and_ui_zero_exit": (
        ["crates/ledr-daemon/src/notify.rs", "apps/ledr-ui/src/**"],
        0.65,
        0.40,
    ),
    "ipc_caller_auth_and_rw_timeout": (
        ["crates/ledr-daemon/src/ipc/**", "crates/ledr-bridge-nm/**"],
        0.65,
        0.40,
    ),
    "wfp_dynamic_session_and_deny_priority": (
        [
            "crates/ledr-sensor-win/src/wfp/**",
            "crates/ledr-daemon/src/firewall/**",
            "crates/ledr-daemon/src/engine/wfp_*.rs",
            "crates/ledr-daemon/src/engine/domain_policy.rs",
        ],
        0.65,
        0.40,
    ),
    "nrd_shutdown_nonblocking_and_checkpoint": (
        [
            "crates/ledr-daemon/src/engine/lifecycle.rs",
            "crates/ledr-daemon/src/engine/nrd.rs",
            "crates/ledr-rules/src/nrd/**",
        ],
        0.65,
        0.40,
    ),
    "phase4_nrd_local_only_and_motw": (
        [
            "extensions/ledr-chrome-mv3/**",
            "crates/ledr-bridge-nm/**",
            "crates/ledr-daemon/src/**",
            "crates/ledr-sensor-win/src/**",
        ],
        0.65,
        0.40,
    ),
    "phase4_clickfix_l15_guard": (
        ["extensions/ledr-chrome-mv3/**"],
        0.70,
        0.40,
    ),
}


def _extract_flag_values(cmd: list[str], flag: str) -> list[str]:
    """Extract consecutive values following a multi-value flag like --paths."""
    idx = cmd.index(flag) + 1
    values: list[str] = []
    while idx < len(cmd) and not cmd[idx].startswith("-"):
        values.append(cmd[idx])
        idx += 1
    return values


def _reject_nonstandard_json_constant(token: str) -> None:
    raise ValueError(f"Non-standard JSON constant is not allowed: {token!r}")


def _load_gate_module(gate_script: Path):
    spec = importlib.util.spec_from_file_location("check_invariants_decision1", gate_script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not create module spec for {gate_script}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestCheckInvariantsWrapper(unittest.TestCase):
    """Specification verification for scripts/check_invariants.py and .agents/invariants.json."""

    def test_T1_01_default_args_assembly(self) -> None:
        """T1-01: Default args include --base main, --preset systems-pre-pr, DEFAULT_PATHS, and UTF-8 env."""
        with tempfile.TemporaryDirectory() as tmp:
            fake_gate = Path(tmp) / "fake_gate.py"
            fake_gate.write_text("# fake gate\n", encoding="utf-8")

            captured: dict[str, object] = {}

            def fake_run(cmd: list[str], env: dict[str, str], check: bool = False) -> mock.Mock:
                captured["cmd"] = cmd
                captured["env"] = env
                captured["check"] = check
                return mock.Mock(returncode=0)

            with mock.patch.object(check_invariants.subprocess, "run", side_effect=fake_run):
                rc = check_invariants.main(
                    ["--gate-script", str(fake_gate), "--dry-run", "--format", "json"],
                    env={"PATH": os.environ.get("PATH", "")},
                )

            self.assertEqual(rc, 0)
            cmd = captured["cmd"]
            assert isinstance(cmd, list)
            self.assertEqual(cmd[0], sys.executable)
            self.assertEqual(Path(cmd[1]), fake_gate.resolve())

            base_idx = cmd.index("--base")
            self.assertEqual(cmd[base_idx + 1], "main")

            preset_idx = cmd.index("--preset")
            self.assertEqual(cmd[preset_idx + 1], "systems-pre-pr")

            self.assertEqual(
                _extract_flag_values(cmd, "--paths"),
                list(check_invariants.DEFAULT_PATHS),
            )
            self.assertIn("--dry-run", cmd)
            fmt_idx = cmd.index("--format")
            self.assertEqual(cmd[fmt_idx + 1], "json")

            child_env = captured["env"]
            assert isinstance(child_env, dict)
            self.assertEqual(child_env["PYTHONUTF8"], "1")
            self.assertEqual(child_env["PYTHONIOENCODING"], "utf-8")
            self.assertFalse(captured["check"])

            # Verify --no-systems-preset omits --preset and optional flags forward.
            args = check_invariants.build_arg_parser().parse_args(
                [
                    "--no-systems-preset",
                    "--strict",
                    "--max-chars",
                    "12345",
                    "--timeout",
                    "15.5",
                ]
            )
            custom_cmd = check_invariants.build_gate_command(args, fake_gate)
            self.assertNotIn("--preset", custom_cmd)
            self.assertIn("--strict", custom_cmd)
            self.assertEqual(custom_cmd[custom_cmd.index("--max-chars") + 1], "12345")
            self.assertEqual(custom_cmd[custom_cmd.index("--timeout") + 1], "15.5")

    def test_T1_02_include_tests_appends_without_duplicates(self) -> None:
        """T1-02: --include-tests appends crates/*/tests/** to --paths without duplicates."""
        parser = check_invariants.build_arg_parser()
        fake_gate = Path("check_invariants_decision1.py")

        # Default paths + --include-tests
        args_default = parser.parse_args(["--include-tests"])
        cmd_default = check_invariants.build_gate_command(args_default, fake_gate)
        paths_default = _extract_flag_values(cmd_default, "--paths")
        self.assertEqual(
            paths_default,
            list(check_invariants.DEFAULT_PATHS) + list(check_invariants.TEST_PATHS),
        )
        self.assertEqual(len(paths_default), len(set(paths_default)))

        # Custom --paths already containing crates/*/tests/** + --include-tests -> deduplicated
        args_dedup = parser.parse_args(
            ["--paths", "crates/ledr-daemon/src/**", "crates/*/tests/**", "--include-tests"]
        )
        cmd_dedup = check_invariants.build_gate_command(args_dedup, fake_gate)
        paths_dedup = _extract_flag_values(cmd_dedup, "--paths")
        self.assertEqual(
            paths_dedup,
            ["crates/ledr-daemon/src/**", "crates/*/tests/**"],
        )

    def test_T1_03_staged_and_diff_file_suppress_auto_base(self) -> None:
        """T1-03: --staged and --diff-file do not auto-attach --base main."""
        parser = check_invariants.build_arg_parser()
        fake_gate = Path("check_invariants_decision1.py")

        cmd_staged = check_invariants.build_gate_command(
            parser.parse_args(["--staged"]), fake_gate
        )
        self.assertIn("--staged", cmd_staged)
        self.assertNotIn("--base", cmd_staged)

        cmd_diff = check_invariants.build_gate_command(
            parser.parse_args(["--diff-file", "sample.diff"]), fake_gate
        )
        self.assertIn("--diff-file", cmd_diff)
        self.assertEqual(cmd_diff[cmd_diff.index("--diff-file") + 1], "sample.diff")
        self.assertNotIn("--base", cmd_diff)

        # Explicit --base is preserved even if --staged is also given.
        cmd_explicit = check_invariants.build_gate_command(
            parser.parse_args(["--base", "origin/main", "--staged"]), fake_gate
        )
        self.assertEqual(cmd_explicit[cmd_explicit.index("--base") + 1], "origin/main")
        self.assertIn("--staged", cmd_explicit)

    def test_T1_04_missing_gate_script_fails_closed_with_exit_2(self) -> None:
        """T1-04: Missing or non-file --gate-script (and env override) exits 2 with stderr message."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            missing = tmp_dir / "does_not_exist.py"

            stderr_buf = io.StringIO()
            with mock.patch.object(check_invariants.subprocess, "run") as mock_run:
                with redirect_stderr(stderr_buf):
                    rc_missing = check_invariants.main(
                        ["--gate-script", str(missing)],
                        env={},
                    )
            self.assertEqual(rc_missing, 2)
            mock_run.assert_not_called()
            self.assertTrue(stderr_buf.getvalue().strip())

            # Directory path (not a file) must also fail closed with exit code 2.
            stderr_dir = io.StringIO()
            with mock.patch.object(check_invariants.subprocess, "run") as mock_run_dir:
                with redirect_stderr(stderr_dir):
                    rc_dir = check_invariants.main(
                        ["--gate-script", str(tmp_dir)],
                        env={},
                    )
            self.assertEqual(rc_dir, 2)
            mock_run_dir.assert_not_called()
            self.assertTrue(stderr_dir.getvalue().strip())

            # Resolution priority: CLI --gate-script > LEDR_INVARIANT_GATE_SCRIPT > default.
            cli_gate = tmp_dir / "cli_gate.py"
            env_gate = tmp_dir / "env_gate.py"
            cli_gate.write_text("# cli\n", encoding="utf-8")
            env_gate.write_text("# env\n", encoding="utf-8")

            self.assertEqual(
                check_invariants.resolve_gate_script(
                    str(cli_gate),
                    env={check_invariants.GATE_SCRIPT_ENV: str(env_gate)},
                ),
                cli_gate.resolve(),
            )
            self.assertEqual(
                check_invariants.resolve_gate_script(
                    None,
                    env={check_invariants.GATE_SCRIPT_ENV: str(env_gate)},
                ),
                env_gate.resolve(),
            )

    def test_T1_05_invariants_json_strict_schema_and_gate_loader(self) -> None:
        """T1-05: .agents/invariants.json is strict BOM-free UTF-8 JSON matching all 10 keys and load_custom_questions."""
        invariants_path = REPO_ROOT / ".agents" / "invariants.json"
        self.assertTrue(invariants_path.is_file(), f"Missing {invariants_path}")

        raw_bytes = invariants_path.read_bytes()
        self.assertFalse(raw_bytes.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM is prohibited")

        text = raw_bytes.decode("utf-8", errors="strict")
        self.assertNotIn("\ufffd", text, "U+FFFD replacement character found")

        parsed = json.loads(text, parse_constant=_reject_nonstandard_json_constant)
        self.assertIsInstance(parsed, dict)
        self.assertEqual(set(parsed.keys()), {"questions"})

        questions = parsed["questions"]
        self.assertIsInstance(questions, dict)
        self.assertEqual(set(questions.keys()), set(EXPECTED_QUESTIONS.keys()))

        for key, (exp_globs, exp_thresh, exp_warn) in EXPECTED_QUESTIONS.items():
            self.assertRegex(key, QUESTION_KEY_RE)
            body = questions[key]
            self.assertIsInstance(body, dict)
            self.assertEqual(body.get("path_globs"), exp_globs)
            self.assertEqual(body.get("threshold"), exp_thresh)
            self.assertEqual(body.get("warn_threshold"), exp_warn)

            for field in ("heading", "description", "source_file", "instructions"):
                val = body.get(field)
                self.assertIsInstance(val, str, f"{key}.{field} must be a string")
                self.assertTrue(val.strip(), f"{key}.{field} must be non-empty")

            # Verify affirmative Yes/No wording (no negative interrogative in opening question).
            opening_sentence = body["instructions"].split("?", 1)[0].lower()
            self.assertTrue(opening_sentence.startswith("does "), f"{key} opening question: {opening_sentence}")
            self.assertNotIn("doesn't", opening_sentence)
            self.assertNotIn("does not", opening_sentence)
            self.assertNotIn("does the git diff not", opening_sentence)

            criteria = body.get("criteria")
            self.assertIsInstance(criteria, dict, f"{key}.criteria must be an object")
            self.assertTrue(str(criteria.get("true_description", "")).strip())
            self.assertTrue(str(criteria.get("false_description", "")).strip())

        try:
            gate_script = check_invariants.resolve_gate_script()
        except FileNotFoundError as exc:
            self.skipTest(f"Global invariant gate script not installed: {exc}")

        gate_mod = _load_gate_module(gate_script)
        loaded = gate_mod.load_custom_questions(invariants_path, REPO_ROOT)
        self.assertEqual(set(loaded.keys()), set(EXPECTED_QUESTIONS.keys()))
        for key, (exp_globs, exp_thresh, exp_warn) in EXPECTED_QUESTIONS.items():
            item = loaded[key]
            self.assertEqual(item.path_globs, exp_globs)
            self.assertAlmostEqual(item.threshold, exp_thresh)
            self.assertAlmostEqual(item.warn_threshold, exp_warn)

    def test_T1_06_dry_run_mock_diff_extracts_proto_and_excludes_artifact(self) -> None:
        """T1-06: Mock diff via real check_invariants_decision1.py extracts proto_frozen_api_compat and excludes ledr_artifact.html."""
        try:
            check_invariants.resolve_gate_script()
        except FileNotFoundError as exc:
            self.skipTest(f"Global invariant gate script not installed: {exc}")

        artifact_marker = "UNIQUE_ARTIFACT_HTML_MARKER_DO_NOT_SEND_TO_API"
        mock_diff = (
            "diff --git a/crates/ledr-proto/src/lib.rs b/crates/ledr-proto/src/lib.rs\n"
            "index 1111111..2222222 100644\n"
            "--- a/crates/ledr-proto/src/lib.rs\n"
            "+++ b/crates/ledr-proto/src/lib.rs\n"
            "@@ -19,3 +19,3 @@\n"
            "-pub const IPC_PROTOCOL_VERSION: u32 = 1;\n"
            "+pub const IPC_PROTOCOL_VERSION: u32 = 2;\n"
            "diff --git a/ledr_artifact.html b/ledr_artifact.html\n"
            "index 3333333..4444444 100644\n"
            "--- a/ledr_artifact.html\n"
            "+++ b/ledr_artifact.html\n"
            "@@ -1,2 +1,3 @@\n"
            " <html>\n"
            f"+<!-- {artifact_marker} -->\n"
            " </html>\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            diff_path = Path(tmp) / "mock.diff"
            diff_path.write_text(mock_diff, encoding="utf-8")

            child_env = dict(os.environ)
            child_env.pop("GEMINI_API_KEY", None)
            child_env["PYTHONUTF8"] = "1"
            child_env["PYTHONIOENCODING"] = "utf-8"

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS_DIR / "check_invariants.py"),
                    "--diff-file",
                    str(diff_path),
                    "--dry-run",
                    "--format",
                    "json",
                ],
                cwd=str(REPO_ROOT),
                env=child_env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )

        self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}\nstdout={proc.stdout}")
        output = json.loads(proc.stdout)
        self.assertEqual(output["status"], "dry_run")
        self.assertEqual(output["exit_code"], 0)

        changed_files = output["changed_files"]
        self.assertIn("crates/ledr-proto/src/lib.rs", changed_files)
        self.assertNotIn("ledr_artifact.html", changed_files)

        questions = output["payload"]["questions"]
        self.assertIn("proto_frozen_api_compat", questions)

        # Other path-scoped rules outside crates/ledr-proto/** should not be included.
        self.assertNotIn("phase4_clickfix_l15_guard", questions)

        input_text = "\n".join(
            block.get("text", "") for block in output["payload"].get("input", [])
        )
        self.assertIn("crates/ledr-proto/src/lib.rs", input_text)
        self.assertNotIn("ledr_artifact.html", input_text)
        self.assertNotIn(artifact_marker, input_text)


if __name__ == "__main__":
    unittest.main()
