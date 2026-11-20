"""Unit tests for LocalEDR Decision 1 visual inspection presets (Track 2)."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
UI_PRESET_PATH = REPO_ROOT / ".agents" / "decision1" / "ui_l13_triage_visual.json"
EXT_PRESET_PATH = REPO_ROOT / ".agents" / "decision1" / "ext_chrome_mv3_visual.json"
RUN_DECISIONS_SCRIPT = (
    Path.home()
    / ".gemini"
    / "config"
    / "plugins"
    / "shared-skills"
    / "skills"
    / "gemini-decisions-api"
    / "scripts"
    / "run_decisions.py"
)

QUESTION_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
CONFLICT_MARKER_RE = re.compile(r"^(?:<{7}(?: |$)|={7}$|>{7}(?: |$))")
NEGATIVE_QUESTION_RE = re.compile(
    r"\b(?:isn't|aren't|doesn't|don't|didn't|won't|can't|couldn't|shouldn't)\b"
    r"|(?:^(?:Is|Are|Do|Does|Did|Can|Could|Should)\s+(?:there\s+no\b|.*\bnot\b))",
    re.IGNORECASE,
)

EXPECTED_UI_TYPES: dict[str, str] = {
    "suspend_banner_visible": "noul",
    "lineage_and_motw_on_first_screen": "noul",
    "three_stage_actions_visible": "noul",
    "has_layout_breakage_or_clipping": "noul",
    "has_redundant_guide_copy": "noul",
    "five_second_triage_clarity": "score",
    "dominant_view": "choice",
}
EXPECTED_DOMINANT_VIEW_KEYS = {
    "view1_triage",
    "view2_flight_recorder",
    "view3_policy_shield",
    "other",
}

EXPECTED_EXT_TYPES: dict[str, str] = {
    "clickfix_warning_visible": "noul",
    "nrd_password_warning_visible": "noul",
    "warning_clipped_or_obscured": "noul",
    "has_unnecessary_alarm_clutter": "noul",
    "warning_actionability": "score",
}

DUMMY_PNG_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def _reject_json_constant(token: str) -> None:
    raise ValueError(f"Non-standard JSON constant {token!r} is not allowed")


def _load_strict_preset(path: Path) -> dict[str, Any]:
    raw_bytes = path.read_bytes()
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raise AssertionError(f"{path} must not contain a UTF-8 BOM")
    text = raw_bytes.decode("utf-8", errors="strict")
    if "\ufffd" in text:
        raise AssertionError(f"{path} contains replacement character U+FFFD")
    for line_no, line in enumerate(text.splitlines(), start=1):
        if CONFLICT_MARKER_RE.match(line):
            raise AssertionError(f"{path}:{line_no} contains a conflict marker")
    parsed = json.loads(text, parse_constant=_reject_json_constant)
    if not isinstance(parsed, dict):
        raise AssertionError(f"{path} must have a JSON object at top level")
    return parsed


def _load_run_decisions_module():
    if not RUN_DECISIONS_SCRIPT.is_file():
        raise AssertionError(f"Global run_decisions.py not found: {RUN_DECISIONS_SCRIPT}")
    spec = importlib.util.spec_from_file_location("run_decisions", RUN_DECISIONS_SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError(f"Failed to load module spec from {RUN_DECISIONS_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VisualPresetsTests(unittest.TestCase):
    """Verify schema, encoding, question contracts, and run_decisions dry-run compatibility."""

    def test_VIS_01_strict_json_utf8_no_bom_no_fffd(self) -> None:
        """VIS-01: Both presets decode strictly as UTF-8 without BOM/U+FFFD and reject NaN/Infinity."""
        for path in (UI_PRESET_PATH, EXT_PRESET_PATH):
            with self.subTest(preset=path.name):
                self.assertTrue(path.is_file(), f"Missing preset file: {path}")
                data = _load_strict_preset(path)
                self.assertGreater(len(data), 0)

    def test_VIS_02_ui_l13_triage_preset_keys_and_types(self) -> None:
        """VIS-02: ui_l13_triage_visual.json has strictly 7 questions matching L-13 contract."""
        data = _load_strict_preset(UI_PRESET_PATH)
        self.assertEqual(len(data), 7)
        self.assertEqual(list(data.keys()), list(EXPECTED_UI_TYPES.keys()))
        for q_key, expected_type in EXPECTED_UI_TYPES.items():
            with self.subTest(question=q_key):
                self.assertRegex(q_key, QUESTION_KEY_RE)
                self.assertEqual(data[q_key].get("type"), expected_type)

    def test_VIS_03_ext_chrome_mv3_preset_keys_and_types(self) -> None:
        """VIS-03: ext_chrome_mv3_visual.json has strictly 5 questions matching Phase 4 contract."""
        data = _load_strict_preset(EXT_PRESET_PATH)
        self.assertEqual(len(data), 5)
        self.assertEqual(list(data.keys()), list(EXPECTED_EXT_TYPES.keys()))
        for q_key, expected_type in EXPECTED_EXT_TYPES.items():
            with self.subTest(question=q_key):
                self.assertRegex(q_key, QUESTION_KEY_RE)
                self.assertEqual(data[q_key].get("type"), expected_type)

    def test_VIS_04_criteria_structure_and_affirmative_instructions(self) -> None:
        """VIS-04: Validate affirmative instructions, noul descriptions, 0-4 score levels, and choice 'other'."""
        for path in (UI_PRESET_PATH, EXT_PRESET_PATH):
            data = _load_strict_preset(path)
            for q_key, q_body in data.items():
                with self.subTest(preset=path.name, question=q_key):
                    instructions = q_body.get("instructions")
                    self.assertIsInstance(instructions, str)
                    self.assertTrue(instructions.strip())
                    self.assertNotRegex(instructions, NEGATIVE_QUESTION_RE)

                    q_type = q_body.get("type")
                    criteria = q_body.get("criteria")
                    if q_type == "noul":
                        self.assertIsInstance(criteria, dict)
                        self.assertEqual(set(criteria.keys()), {"true_description", "false_description"})
                        for field in ("true_description", "false_description"):
                            val = criteria.get(field)
                            self.assertIsInstance(val, str)
                            self.assertTrue(val.strip(), f"{q_key}.{field} must be non-empty")
                    elif q_type == "score":
                        self.assertIsInstance(criteria, list)
                        self.assertEqual(len(criteria), 5)
                        for idx, item in enumerate(criteria):
                            self.assertIsInstance(item, str)
                            prefix = f"{idx}: "
                            self.assertTrue(
                                item.startswith(prefix),
                                f"{q_key}.criteria[{idx}] must start with {prefix!r}: {item!r}",
                            )
                            self.assertTrue(item[len(prefix) :].strip())
                    elif q_type == "choice":
                        self.assertIsInstance(criteria, dict)
                        self.assertIn("other", criteria)
                        if q_key == "dominant_view":
                            self.assertEqual(set(criteria.keys()), EXPECTED_DOMINANT_VIEW_KEYS)
                        for opt_key, opt_desc in criteria.items():
                            self.assertIsInstance(opt_desc, str)
                            self.assertTrue(opt_desc.strip(), f"{q_key}.criteria[{opt_key!r}] must be non-empty")
                    else:
                        self.fail(f"Unexpected question type {q_type!r} in {q_key}")

    def test_VIS_05_validate_payload_via_global_run_decisions(self) -> None:
        """VIS-05: Imported run_decisions.validate_payload returns zero errors for text and image payloads."""
        run_decisions = _load_run_decisions_module()
        for path in (UI_PRESET_PATH, EXT_PRESET_PATH):
            questions = _load_strict_preset(path)
            for label, input_blocks in (
                ("text", [{"type": "text", "text": "dry-run placeholder"}]),
                (
                    "image",
                    [
                        {
                            "type": "image",
                            "data": DUMMY_PNG_BASE64,
                            "mime_type": "image/png",
                            "resolution": "medium",
                        }
                    ],
                ),
            ):
                with self.subTest(preset=path.name, input_kind=label):
                    payload = {
                        "model": run_decisions.DEFAULT_MODEL,
                        "input": input_blocks,
                        "questions": questions,
                    }
                    errors = run_decisions.validate_payload(payload)
                    self.assertEqual(errors, [])

    def test_VIS_06_subprocess_dry_run_without_api_key(self) -> None:
        """VIS-06: run_decisions.py --dry-run succeeds with exit code 0 and no GEMINI_API_KEY."""
        self.assertTrue(RUN_DECISIONS_SCRIPT.is_file(), f"Missing script: {RUN_DECISIONS_SCRIPT}")
        env = os.environ.copy()
        env.pop("GEMINI_API_KEY", None)
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"

        for path, expected_keys in (
            (UI_PRESET_PATH, list(EXPECTED_UI_TYPES.keys())),
            (EXT_PRESET_PATH, list(EXPECTED_EXT_TYPES.keys())),
        ):
            with self.subTest(preset=path.name):
                res = subprocess.run(
                    [
                        sys.executable,
                        str(RUN_DECISIONS_SCRIPT),
                        "--text",
                        "dry-run placeholder",
                        "--questions",
                        str(path),
                        "--dry-run",
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    env=env,
                    check=False,
                )
                self.assertEqual(res.returncode, 0, msg=res.stderr)
                self.assertEqual(res.stderr, "")
                payload = json.loads(res.stdout, parse_constant=_reject_json_constant)
                self.assertEqual(payload.get("model"), "gemini-decision-1")
                self.assertEqual(list(payload.get("questions", {}).keys()), expected_keys)


if __name__ == "__main__":
    unittest.main()
