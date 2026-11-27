#!/usr/bin/env python3
"""Specification tests for LocalEDR release scripts (REL-01..REL-07).

Pure Python 3.11+ stdlib ``unittest`` suite (zero external packages).
"""

from __future__ import annotations

import base64
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import build_release_artifacts  # noqa: E402
import release_verify  # noqa: E402

_PS_CORE_MODULE_PATH_RE = re.compile(
    r"[\\/]PowerShell(?:[\\/][^\\/]+)*[\\/]Modules(?:[\\/]|$)",
    re.IGNORECASE,
)


def _sanitize_ps51_env(base_env: dict[str, str] | None = None) -> dict[str, str]:
    """Return an environment dict safe for Windows PowerShell 5.1 (powershell.exe).

    When invoked from PowerShell 7+ (pwsh), inherited PSModulePath contains PS 7
    module directories (e.g. ``C:\\Program Files\\PowerShell\\7\\Modules``) that break
    inbox module autoloading (``Microsoft.PowerShell.Security``) in powershell.exe.
    """
    env = dict(os.environ if base_env is None else base_env)
    ps_mod_key = next(
        (k for k in env if k.lower() == "psmodulepath"),
        "PSModulePath",
    )
    raw_ps_mod = env.get(ps_mod_key, "")
    system_root = next(
        (v for k, v in env.items() if k.lower() == "systemroot" and v),
        r"C:\Windows",
    )
    inbox_modules = (
        f"{system_root.rstrip(chr(92) + '/')}\\System32\\WindowsPowerShell\\v1.0\\Modules"
    )

    cleaned: list[str] = []
    seen_lower: set[str] = set()
    for raw_entry in raw_ps_mod.split(";"):
        entry = raw_entry.strip()
        if not entry or _PS_CORE_MODULE_PATH_RE.search(entry):
            continue
        key = entry.lower()
        if key not in seen_lower:
            seen_lower.add(key)
            cleaned.append(entry)

    if inbox_modules.lower() not in seen_lower:
        cleaned.append(inbox_modules)

    for k in [k for k in env if k.lower() == "psmodulepath"]:
        del env[k]
    env["PSModulePath"] = ";".join(cleaned)
    return env


def _extract_workflow_job_block(workflow_text: str, job_name: str) -> str:
    """Extract a top-level job block under ``jobs:`` by 2-space YAML indentation."""
    match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\r?\n(.*?)(?=^  [A-Za-z0-9_-]+:\r?\n|\Z)",
        workflow_text,
    )
    if match is None:
        raise AssertionError(f"Workflow must define job {job_name!r}")
    return match.group(1)


def _create_mock_repo(root: Path, version: str = "0.1.0") -> tuple[Path, Path, Path]:
    (root / "crates").mkdir(parents=True, exist_ok=True)
    (root / "apps" / "ledr-ui").mkdir(parents=True, exist_ok=True)
    (root / "extensions" / "ledr-chrome-mv3" / "lib").mkdir(parents=True, exist_ok=True)
    (root / "extensions" / "ledr-chrome-mv3" / "rules").mkdir(parents=True, exist_ok=True)
    (root / "extensions" / "ledr-chrome-mv3" / "tests").mkdir(parents=True, exist_ok=True)
    (root / "extensions" / "ledr-chrome-mv3" / "_metadata").mkdir(parents=True, exist_ok=True)
    (root / "rules").mkdir(parents=True, exist_ok=True)
    (root / "packaging" / "windows").mkdir(parents=True, exist_ok=True)

    (root / "Cargo.toml").write_text(
        f'[workspace]\nmembers = []\n\n[workspace.package]\nversion = "{version}"\n',
        encoding="utf-8",
    )
    tauri_src = json.loads(
        (REPO_ROOT / "apps" / "ledr-ui" / "tauri.conf.json").read_text(encoding="utf-8")
    )
    tauri_src["version"] = version
    (root / "apps" / "ledr-ui" / "tauri.conf.json").write_text(
        json.dumps(tauri_src, indent=2), encoding="utf-8"
    )

    ext_src = json.loads(
        (REPO_ROOT / "extensions" / "ledr-chrome-mv3" / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    ext_src["version"] = version
    (root / "extensions" / "ledr-chrome-mv3" / "manifest.json").write_text(
        json.dumps(ext_src, indent=2), encoding="utf-8"
    )
    for rel in (
        "background.js",
        "content.js",
        "content_main.js",
        "popup.html",
        "popup.js",
        "popup.css",
        "rules/dnr_static.json",
        "lib/clickfix.js",
        "lib/dnr.js",
        "lib/domain_risk.js",
        "lib/downloads.js",
        "lib/native_bridge.js",
        "package.json",
        "tests/dummy.test.mjs",
        "_metadata/verified_contents.json",
    ):
        (root / "extensions" / "ledr-chrome-mv3" / rel).write_text(
            "// mock\n" if not rel.endswith(".json") else "{}",
            encoding="utf-8",
        )

    for rule in ("lotl_core.json", "default_allowlist.json"):
        (root / "rules" / rule).write_text("{}", encoding="utf-8")

    (root / "packaging" / "windows" / "install.ps1").write_text("# mock\n", encoding="utf-8")
    (root / "packaging" / "windows" / "uninstall.ps1").write_text("# mock\n", encoding="utf-8")

    bin_dir = root / "target" / "release"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for exe in (
        "ledr-daemon.exe",
        "ledr-ui.exe",
        "ledr-bridge-nm.exe",
        "ledr-auth-helper.exe",
        "ledr-daemon.pdb",
    ):
        (bin_dir / exe).write_bytes(b"MZ-MOCK-" + exe.encode("ascii"))

    installer_exe = root / "mock-setup.exe"
    installer_exe.write_bytes(b"MZ-NSIS-INSTALLER-PAYLOAD" * 16)

    pub_keys_path = root / "packaging" / "update-public-keys.json"
    shutil.copyfile(REPO_ROOT / "packaging" / "update-public-keys.json", pub_keys_path)

    return bin_dir, installer_exe, pub_keys_path


class TestReleaseScripts(unittest.TestCase):
    # REL-01: RFC 8032 Ed25519 Vectors 1-3, PKCS#8 PEM, strict S < L & key status checks
    def test_rel_01_ed25519_vectors_pem_and_strict_checks(self) -> None:
        vectors = [
            # Vector 1 (empty message)
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            # Vector 2 (1-byte message 0x72)
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            # Vector 3 (2-byte message 0xaf82)
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ]
        for seed_hex, pub_hex, msg_hex, sig_hex in vectors:
            seed = bytes.fromhex(seed_hex)
            expected_pub = bytes.fromhex(pub_hex)
            msg = bytes.fromhex(msg_hex)
            expected_sig = bytes.fromhex(sig_hex)

            actual_pub = release_verify.ed25519_pubkey_from_seed(seed)
            self.assertEqual(actual_pub, expected_pub)

            actual_sig = release_verify.ed25519_sign(seed, msg)
            self.assertEqual(actual_sig, expected_sig)
            self.assertTrue(release_verify.ed25519_verify_strict(expected_pub, msg, expected_sig))
            self.assertFalse(
                release_verify.ed25519_verify_strict(expected_pub, msg + b"\x00", expected_sig)
            )

            # PKCS#8 PEM roundtrip & 64-byte seed+pub roundtrip
            pem = release_verify.encode_pkcs8_pem_from_seed(seed)
            self.assertEqual(release_verify.parse_ed25519_private_seed(pem), seed)
            combo_b64 = base64.b64encode(seed + expected_pub).decode("ascii")
            self.assertEqual(release_verify.parse_ed25519_private_seed(combo_b64), seed)

            # Non-canonical S >= L must be rejected
            s_val = int.from_bytes(expected_sig[32:], "little") + release_verify._L
            if s_val < (1 << 256):
                malleated_sig = expected_sig[:32] + s_val.to_bytes(32, "little")
                self.assertFalse(
                    release_verify.ed25519_verify_strict(expected_pub, msg, malleated_sig)
                )

    # REL-02: preflight on actual repo and version/key failure paths
    def test_rel_02_preflight_real_and_mismatch(self) -> None:
        real_res = release_verify.run_preflight(
            repo_root=REPO_ROOT,
            public_keys_path=REPO_ROOT / "packaging" / "update-public-keys.json",
            expect_tag="v0.1.0",
            require_active_key=True,
        )
        self.assertEqual(real_res["version"], "0.1.0")
        self.assertEqual(real_res["extension_id"], release_verify.EXPECTED_CHROME_EXTENSION_ID)
        self.assertIn("prod-2026-11", real_res["active_key_ids"])

        with self.assertRaises(ValueError):
            release_verify.run_preflight(
                repo_root=REPO_ROOT,
                public_keys_path=REPO_ROOT / "packaging" / "update-public-keys.json",
                expect_tag="v9.9.9",
            )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _, _, pub_keys = _create_mock_repo(tmp_path, "0.2.0")
            pub_keys.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "keys": [
                            {
                                "key_id": "placeholder-unconfigured",
                                "public_key_b64": "UNCONFIGURED_PLACEHOLDER",
                                "status": "disabled",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                release_verify.run_preflight(
                    repo_root=tmp_path,
                    public_keys_path=pub_keys,
                    require_active_key=True,
                )

            # Break tauri.conf.json version sync
            tauri_p = tmp_path / "apps" / "ledr-ui" / "tauri.conf.json"
            t = json.loads(tauri_p.read_text(encoding="utf-8"))
            t["version"] = "0.2.1"
            tauri_p.write_text(json.dumps(t), encoding="utf-8")
            with self.assertRaises(ValueError):
                release_verify.run_preflight(repo_root=tmp_path, public_keys_path=pub_keys)

    # REL-03: End-to-end build_release_artifacts + verify-dist
    def test_rel_03_build_and_verify_dist_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir, installer_exe, pub_keys = _create_mock_repo(tmp_path, "0.1.0")
            priv_file = tmp_path / "signing.key"
            kg = release_verify.run_keygen(
                key_id="ci-test-key",
                fmt="pkcs8-pem",
                write_public_keys=pub_keys,
                write_private_key_file=priv_file,
            )
            self.assertNotIn("private_key", kg)

            out_dir = tmp_path / "dist"
            built = build_release_artifacts.build_release_artifacts(
                repo_root=tmp_path,
                bin_dir=bin_dir,
                installer_exe=installer_exe,
                out_dir=out_dir,
                public_keys_path=pub_keys,
                private_key_file=priv_file,
            )
            self.assertEqual(len(list(out_dir.iterdir())), 6)

            with zipfile.ZipFile(built["chrome_ext_zip"], "r") as zf:
                names = set(zf.namelist())
                self.assertIn("manifest.json", names)
                self.assertIn("lib/clickfix.js", names)
                self.assertFalse(any("_metadata" in n or "tests/" in n or n == "package.json" for n in names))

            with zipfile.ZipFile(built["portable_zip"], "r") as zf:
                names = set(zf.namelist())
                self.assertIn("ledr-daemon.exe", names)
                self.assertIn("install.ps1", names)
                self.assertFalse(any(n.endswith(".pdb") for n in names))

    # REL-04: Negative tamper matrix for verify-dist
    def test_rel_04_tamper_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir, installer_exe, pub_keys = _create_mock_repo(tmp_path, "0.1.0")
            priv_file = tmp_path / "signing.key"
            release_verify.run_keygen(
                key_id="tamper-key",
                write_public_keys=pub_keys,
                write_private_key_file=priv_file,
            )
            base_dist = tmp_path / "dist-base"
            build_release_artifacts.build_release_artifacts(
                repo_root=tmp_path,
                bin_dir=bin_dir,
                installer_exe=installer_exe,
                out_dir=base_dist,
                public_keys_path=pub_keys,
                private_key_file=priv_file,
            )

            def clone_dist(name: str) -> Path:
                d = tmp_path / f"dist-{name}"
                shutil.copytree(base_dist, d)
                return d

            # 1. 1-byte edit to update-manifest.json fails signature verification
            d1 = clone_dist("edit-manifest")
            mp = d1 / "update-manifest.json"
            mp.write_bytes(mp.read_bytes().replace(b"LocalEDR", b"LocalEDr", 1))
            with self.assertRaises(ValueError):
                release_verify.verify_dist(dist_dir=d1, public_keys_path=pub_keys)

            # 2. Wrong algorithm in .sig
            d2 = clone_dist("bad-alg")
            sp = d2 / "update-manifest.json.sig"
            sig_doc = json.loads(sp.read_text(encoding="utf-8"))
            sig_doc["algorithm"] = "rsa"
            sp.write_text(json.dumps(sig_doc), encoding="utf-8")
            with self.assertRaises(ValueError):
                release_verify.verify_dist(dist_dir=d2, public_keys_path=pub_keys)

            # 3. Disabled/revoked key rejected
            d3 = clone_dist("revoked-key")
            revoked_keys = tmp_path / "revoked-keys.json"
            kdoc = json.loads(pub_keys.read_text(encoding="utf-8"))
            kdoc["keys"][0]["status"] = "revoked"
            revoked_keys.write_text(json.dumps(kdoc), encoding="utf-8")
            with self.assertRaises(ValueError):
                release_verify.verify_dist(dist_dir=d3, public_keys_path=revoked_keys)

            # 4. Extra .sig file in dist_dir rejected
            d4 = clone_dist("extra-sig")
            (d4 / "extra.sig").write_text("junk", encoding="utf-8")
            with self.assertRaises(ValueError):
                release_verify.verify_dist(dist_dir=d4, public_keys_path=pub_keys)

            # 5. Tampered installer binary fails sha256/size verification
            d5 = clone_dist("bad-exe")
            (d5 / "LocalEDR-Setup-v0.1.0-win-x64.exe").write_bytes(b"TAMPERED")
            with self.assertRaises(ValueError):
                release_verify.verify_dist(dist_dir=d5, public_keys_path=pub_keys)

            # 6. Extension zip containing _metadata/ rejected
            d6 = clone_dist("ext-metadata")
            ext_zip = d6 / "LocalEDR-chrome-ext-v0.1.0.zip"
            with zipfile.ZipFile(ext_zip, "a") as zf:
                zf.writestr("_metadata/verified_contents.json", "{}")
            with self.assertRaises(ValueError):
                release_verify.verify_dist(dist_dir=d6, public_keys_path=pub_keys)

            # 7. Path traversal filename in signed manifest rejected
            d7 = clone_dist("bad-filename")
            m_doc = json.loads((d7 / "update-manifest.json").read_text(encoding="utf-8"))
            m_doc["filename"] = "../evil.exe"
            m_bytes = (json.dumps(m_doc, indent=2) + "\n").encode("utf-8")
            (d7 / "update-manifest.json").write_bytes(m_bytes)
            seed = release_verify.parse_ed25519_private_seed(priv_file.read_text(encoding="utf-8"))
            sig_env = {
                "schema_version": 1,
                "key_id": "tamper-key",
                "algorithm": "ed25519",
                "signature_b64": base64.b64encode(release_verify.ed25519_sign(seed, m_bytes)).decode("ascii"),
            }
            (d7 / "update-manifest.json.sig").write_text(json.dumps(sig_env), encoding="utf-8")
            with self.assertRaises(ValueError):
                release_verify.verify_dist(dist_dir=d7, public_keys_path=pub_keys)

            # 8. Bad release_notes_url / wrong extension_id / missing SHA256SUMS / tests/ in zip
            for case_name, mutator in (
                ("bad-notes-url", lambda d: d.__setitem__("release_notes_url", "https://evil.example/notes")),
                ("bad-ext-id", lambda d: d["chrome_extension"].__setitem__("extension_id", "a" * 32)),
                ("bad-size", lambda d: d.__setitem__("size_bytes", 999999999)),
            ):
                dc = clone_dist(case_name)
                md = json.loads((dc / "update-manifest.json").read_text(encoding="utf-8"))
                mutator(md)
                mb = (json.dumps(md, indent=2) + "\n").encode("utf-8")
                (dc / "update-manifest.json").write_bytes(mb)
                se = {
                    "schema_version": 1,
                    "key_id": "tamper-key",
                    "algorithm": "ed25519",
                    "signature_b64": base64.b64encode(release_verify.ed25519_sign(seed, mb)).decode("ascii"),
                }
                (dc / "update-manifest.json.sig").write_text(json.dumps(se), encoding="utf-8")
                with self.assertRaises(ValueError):
                    release_verify.verify_dist(dist_dir=dc, public_keys_path=pub_keys)

            d9 = clone_dist("missing-sum")
            sums_lines = (d9 / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
            (d9 / "SHA256SUMS.txt").write_text("\n".join(sums_lines[:-1]) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                release_verify.verify_dist(dist_dir=d9, public_keys_path=pub_keys)

            d10 = clone_dist("ext-tests")
            with zipfile.ZipFile(d10 / "LocalEDR-chrome-ext-v0.1.0.zip", "a") as zf:
                zf.writestr("tests/leak.test.mjs", "// bad")
            with self.assertRaises(ValueError):
                release_verify.verify_dist(dist_dir=d10, public_keys_path=pub_keys)

    # REL-05: CLI exit codes and secret non-echoing
    def test_rel_05_cli_exit_codes_and_secret_hygiene(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir, installer_exe, pub_keys = _create_mock_repo(tmp_path, "0.1.0")
            out_dir = tmp_path / "dist"
            env_name = "TEST_LEDR_SIGNING_KEY"
            kg = release_verify.run_keygen(key_id="env-key", write_public_keys=pub_keys)
            secret_val = kg["private_key"]

            old_env = os.environ.get(env_name)
            os.environ[env_name] = secret_val
            try:
                buf_out = io.StringIO()
                buf_err = io.StringIO()
                with redirect_stdout(buf_out), redirect_stderr(buf_err):
                    rc = build_release_artifacts.main(
                        [
                            "--repo-root",
                            str(tmp_path),
                            "--bin-dir",
                            str(bin_dir),
                            "--installer-exe",
                            str(installer_exe),
                            "--out-dir",
                            str(out_dir),
                            "--public-keys",
                            str(pub_keys),
                            "--private-key-env",
                            env_name,
                        ]
                    )
                self.assertEqual(rc, 0)
                self.assertNotIn(secret_val, buf_out.getvalue())
                self.assertNotIn(secret_val, buf_err.getvalue())

                # Invalid env key fails non-zero without echoing secret
                os.environ[env_name] = "NOT_A_VALID_PRIVATE_KEY_SECRET_ABC"
                buf_out2 = io.StringIO()
                buf_err2 = io.StringIO()
                with redirect_stdout(buf_out2), redirect_stderr(buf_err2):
                    rc2 = release_verify.main(
                        [
                            "preflight",
                            "--repo-root",
                            str(tmp_path),
                            "--public-keys",
                            str(pub_keys),
                            "--require-active-key",
                            "--private-key-env",
                            env_name,
                        ]
                    )
                self.assertEqual(rc2, 1)
                self.assertNotIn("NOT_A_VALID_PRIVATE_KEY_SECRET_ABC", buf_out2.getvalue())
                self.assertNotIn("NOT_A_VALID_PRIVATE_KEY_SECRET_ABC", buf_err2.getvalue())
            finally:
                if old_env is None:
                    os.environ.pop(env_name, None)
                else:
                    os.environ[env_name] = old_env

    # REL-06: Same-path installer in out_dir and LF-only SHA256SUMS.txt enforcement
    def test_rel_06_same_path_installer_and_lf_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir, installer_exe, pub_keys = _create_mock_repo(tmp_path, "0.1.0")
            priv_file = tmp_path / "signing.key"
            release_verify.run_keygen(
                key_id="same-path-key",
                write_public_keys=pub_keys,
                write_private_key_file=priv_file,
            )

            out_dir = tmp_path / "dist"
            out_dir.mkdir(parents=True, exist_ok=True)
            preplaced_setup = out_dir / "LocalEDR-Setup-v0.1.0-win-x64.exe"
            shutil.copyfile(installer_exe, preplaced_setup)
            expected_bytes = preplaced_setup.read_bytes()

            built = build_release_artifacts.build_release_artifacts(
                repo_root=tmp_path,
                bin_dir=bin_dir,
                installer_exe=preplaced_setup,
                out_dir=out_dir,
                public_keys_path=pub_keys,
                private_key_file=priv_file,
                expect_tag="v0.1.0",
            )
            self.assertEqual(Path(built["setup_exe"]).resolve(), preplaced_setup.resolve())
            self.assertEqual(preplaced_setup.read_bytes(), expected_bytes)

            sums_path = Path(built["sha256sums"])
            sums_bytes = sums_path.read_bytes()
            self.assertNotIn(b"\r", sums_bytes)
            self.assertTrue(sums_bytes.endswith(b"\n"))

            verified = release_verify.verify_dist(
                dist_dir=out_dir,
                public_keys_path=pub_keys,
                expect_tag="v0.1.0",
                expect_version="0.1.0",
            )
            self.assertEqual(verified["tag"], "v0.1.0")

            # CRLF in SHA256SUMS.txt must be rejected by verify_dist
            crlf_dist = tmp_path / "dist-crlf"
            shutil.copytree(out_dir, crlf_dist)
            crlf_sums = crlf_dist / "SHA256SUMS.txt"
            crlf_sums.write_bytes(sums_bytes.replace(b"\n", b"\r\n"))
            with self.assertRaisesRegex(ValueError, "LF line endings"):
                release_verify.verify_dist(dist_dir=crlf_dist, public_keys_path=pub_keys)

    # REL-07: Rust serde_json / u32 parity and case-insensitive archive checks
    def test_rel_07_serde_u32_parity_and_case_insensitive_archive_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir, installer_exe, pub_keys = _create_mock_repo(tmp_path, "0.1.0")
            priv_file = tmp_path / "signing.key"
            release_verify.run_keygen(
                key_id="parity-key",
                write_public_keys=pub_keys,
                write_private_key_file=priv_file,
            )
            base_dist = tmp_path / "dist-base"
            build_release_artifacts.build_release_artifacts(
                repo_root=tmp_path,
                bin_dir=bin_dir,
                installer_exe=installer_exe,
                out_dir=base_dist,
                public_keys_path=pub_keys,
                private_key_file=priv_file,
            )

            seed = release_verify.parse_ed25519_private_seed(priv_file.read_text(encoding="utf-8"))
            active_keys = release_verify.parse_public_key_ring(pub_keys, require_active_key=True)
            base_manifest_bytes = (base_dist / "update-manifest.json").read_bytes()
            base_manifest_doc = json.loads(base_manifest_bytes.decode("utf-8"))

            # 1. schema_version: true rejected in public keys, manifest, and signature envelope
            bool_keys = tmp_path / "bool-keys.json"
            kdoc = json.loads(pub_keys.read_text(encoding="utf-8"))
            kdoc["schema_version"] = True
            bool_keys.write_text(json.dumps(kdoc), encoding="utf-8")
            with self.assertRaises(ValueError):
                release_verify.parse_public_key_ring(bool_keys, require_active_key=False)

            bool_manifest = dict(base_manifest_doc)
            bool_manifest["schema_version"] = True
            with self.assertRaises(ValueError):
                release_verify.validate_manifest_structure(
                    (json.dumps(bool_manifest, indent=2) + "\n").encode("utf-8")
                )

            bool_sig_env = {
                "schema_version": True,
                "key_id": "parity-key",
                "algorithm": "ed25519",
                "signature_b64": base64.b64encode(
                    release_verify.ed25519_sign(seed, base_manifest_bytes)
                ).decode("ascii"),
            }
            with self.assertRaises(ValueError):
                release_verify.verify_signature_envelope_and_bytes(
                    base_manifest_bytes,
                    json.dumps(bool_sig_env).encode("utf-8"),
                    active_keys,
                )

            # 2. Non-standard JSON constants (NaN / Infinity) rejected in manifest & .sig
            nan_manifest_bytes = base_manifest_bytes.replace(
                b'"released_at": "' + base_manifest_doc["released_at"].encode("utf-8") + b'"',
                b'"released_at": NaN',
            )
            with self.assertRaises(ValueError):
                release_verify.validate_manifest_structure(nan_manifest_bytes)

            sig_doc = json.loads((base_dist / "update-manifest.json.sig").read_text(encoding="utf-8"))
            sig_doc["extra"] = 1
            nan_sig_bytes = json.dumps(sig_doc).replace(": 1}", ": Infinity}").encode("utf-8")
            with self.assertRaises(ValueError):
                release_verify.verify_signature_envelope_and_bytes(
                    base_manifest_bytes,
                    nan_sig_bytes,
                    active_keys,
                )

            # 3. Control / whitespace characters rejected in release_notes_url and download_url
            for bad_notes in (
                base_manifest_doc["release_notes_url"] + "\nhttps://evil.example",
                base_manifest_doc["release_notes_url"] + "\r",
                base_manifest_doc["release_notes_url"] + "\t",
                base_manifest_doc["release_notes_url"] + " extra",
            ):
                ctrl_manifest = dict(base_manifest_doc)
                ctrl_manifest["release_notes_url"] = bad_notes
                with self.assertRaises(ValueError):
                    release_verify.validate_manifest_structure(
                        (json.dumps(ctrl_manifest, indent=2) + "\n").encode("utf-8")
                    )

            with self.assertRaises(ValueError):
                release_verify.validate_download_url(base_manifest_doc["download_url"] + "\n")

            # 4. Case-insensitive forbidden archive segments (Tests/, _METADATA/) rejected
            for bad_entry in ("Tests/leak.test.mjs", "_METADATA/verified_contents.json"):
                d_case = tmp_path / ("dist-" + bad_entry.split("/")[0].lower())
                shutil.copytree(base_dist, d_case)
                with zipfile.ZipFile(d_case / "LocalEDR-chrome-ext-v0.1.0.zip", "a") as zf:
                    zf.writestr(bad_entry, "{}")
                with self.assertRaises(ValueError):
                    release_verify.verify_dist(dist_dir=d_case, public_keys_path=pub_keys)

    # REL-08: Release workflow & Windows PowerShell packaging invariants
    def test_rel_08_workflow_and_packaging_script_invariants(self) -> None:
        release_yml = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        # Checkout ref pinning across preflight, verify, build, package, publish
        self.assertGreaterEqual(len(re.findall(r"uses:\s*actions/checkout@v4", release_yml)), 5)
        self.assertIn("ref: ${{ github.sha }}", release_yml)
        self.assertEqual(
            release_yml.count("ref: ${{ needs.preflight.outputs.source_sha }}"), 4
        )

        rel_preflight_block = _extract_workflow_job_block(release_yml, "preflight")
        self.assertIn("runs-on: ubuntu-latest", rel_preflight_block)
        self.assertIn("ref: ${{ github.sha }}", rel_preflight_block)
        self.assertIn('refs/tags/${RELEASE_TAG}^{commit}', rel_preflight_block)
        self.assertIn("scripts/release_verify.py preflight", rel_preflight_block)

        rel_verify_block = _extract_workflow_job_block(release_yml, "verify")
        self.assertIn("runs-on: windows-latest", rel_verify_block)
        self.assertIn("needs: preflight", rel_verify_block)
        self.assertIn("ref: ${{ needs.preflight.outputs.source_sha }}", rel_verify_block)
        self.assertIn("CARGO_PROFILE_DEV_DEBUG: line-tables-only", rel_verify_block)
        self.assertIn("components: clippy", rel_verify_block)
        self.assertIn('shared-key: "win-x64-dev"', rel_verify_block)
        self.assertIn("save-if: ${{ github.ref == 'refs/heads/main' }}", rel_verify_block)
        self.assertIn("cargo clippy", rel_verify_block)
        self.assertIn("cargo test --workspace --locked", rel_verify_block)
        self.assertIn("phase4_ui.test.mjs", rel_verify_block)
        self.assertNotIn("LEDR_UPDATE_SIGNING_PRIVATE_KEY", rel_verify_block)
        self.assertNotIn("LEDR_UPDATE_SIGNING_KEY_ID", rel_verify_block)

        rel_build_block = _extract_workflow_job_block(release_yml, "build")
        self.assertIn("runs-on: windows-latest", rel_build_block)
        self.assertIn("needs: preflight", rel_build_block)
        self.assertIn("ref: ${{ needs.preflight.outputs.source_sha }}", rel_build_block)
        self.assertIn("PYTHONUTF8: '1'", rel_build_block)
        self.assertIn("PYTHONIOENCODING: utf-8", rel_build_block)
        self.assertIn("scripts/test_release_scripts.py", rel_build_block)
        self.assertIn("makensis.exe", rel_build_block)
        self.assertIn("/VERSION", rel_build_block)
        self.assertIn('shared-key: "win-x64-release"', rel_build_block)
        self.assertIn("save-if: ${{ github.ref == 'refs/heads/main' }}", rel_build_block)
        self.assertIn("cargo build --release", rel_build_block)
        self.assertIn("unsigned-build-outputs", rel_build_block)
        self.assertNotIn("LEDR_UPDATE_SIGNING_PRIVATE_KEY", rel_build_block)
        self.assertNotIn("LEDR_UPDATE_SIGNING_KEY_ID", rel_build_block)
        self.assertNotIn("cargo clippy", rel_build_block)
        self.assertNotIn("cargo test", rel_build_block)
        self.assertNotIn("--use-enhanced-exit-codes", rel_build_block)
        self.assertNotIn("components: clippy", rel_build_block)

        rel_package_block = _extract_workflow_job_block(release_yml, "package")
        self.assertIn("runs-on: ubuntu-latest", rel_package_block)
        self.assertIn("needs: [preflight, verify, build]", rel_package_block)
        self.assertIn("ref: ${{ needs.preflight.outputs.source_sha }}", rel_package_block)
        self.assertIn("unsigned-build-outputs", rel_package_block)
        self.assertIn("scripts/build_release_artifacts.py", rel_package_block)
        self.assertIn("--key-id dry-run-test", rel_package_block)
        self.assertIn("scripts/release_verify.py verify-dist", rel_package_block)
        self.assertIn("release-dist", rel_package_block)

        rel_publish_block = _extract_workflow_job_block(release_yml, "publish")
        self.assertIn("runs-on: ubuntu-latest", rel_publish_block)
        self.assertIn("needs: [preflight, verify, build, package]", rel_publish_block)
        self.assertIn("if: needs.preflight.outputs.dry_run == 'false'", rel_publish_block)
        self.assertIn("ref: ${{ needs.preflight.outputs.source_sha }}", rel_publish_block)
        self.assertIn('refs/tags/${TAG}^{commit}', rel_publish_block)
        self.assertIn("--verify-tag", rel_publish_block)
        self.assertIn('gh release create "$TAG" --draft --verify-tag', rel_publish_block)
        self.assertIn('gh release edit "$TAG" --draft=false', rel_publish_block)

        install_ps1 = (REPO_ROOT / "packaging" / "windows" / "install.ps1").read_text(
            encoding="utf-8"
        )
        uninstall_ps1 = (REPO_ROOT / "packaging" / "windows" / "uninstall.ps1").read_text(
            encoding="utf-8"
        )

        # Rollback preservation & ACL hardening markers in install.ps1 (PS 5.1 + PS 7 compatible)
        self.assertIn("$rollbackRestoreFailed", install_ps1)
        self.assertIn("PurgeAccessRules", install_ps1)
        self.assertIn("SetAccessRuleProtection($true, $false)", install_ps1)
        self.assertIn("Reset-DataSubdirInheritedAcl", install_ps1)
        self.assertIn("Get-Acl -LiteralPath", install_ps1)
        self.assertIn("Set-Acl -LiteralPath", install_ps1)
        self.assertNotIn(".GetAccessControl(", install_ps1)
        self.assertNotIn(".SetAccessControl(", install_ps1)
        self.assertNotIn(".GetAccessControl(", uninstall_ps1)
        self.assertNotIn(".SetAccessControl(", uninstall_ps1)

        # Windows execution of test_release_scripts.py and cache-aligned rust-windows in ci.yml
        ci_yml = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        ci_win_pkg_block = _extract_workflow_job_block(ci_yml, "windows-packaging-tests")
        self.assertIn("runs-on: windows-latest", ci_win_pkg_block)
        self.assertIn(
            "if: needs.changes.outputs.windows_packaging == 'true'", ci_win_pkg_block
        )
        self.assertIn("PYTHONUTF8: '1'", ci_win_pkg_block)
        self.assertIn("PYTHONIOENCODING: utf-8", ci_win_pkg_block)
        self.assertIn("scripts/test_release_scripts.py", ci_win_pkg_block)
        self.assertIn('"windows-packaging-tests": "windows_packaging"', ci_yml)

        ci_rust_win_block = _extract_workflow_job_block(ci_yml, "rust-windows")
        self.assertIn("runs-on: windows-latest", ci_rust_win_block)
        self.assertIn("CARGO_PROFILE_DEV_DEBUG: line-tables-only", ci_rust_win_block)
        self.assertIn("components: clippy", ci_rust_win_block)
        self.assertIn('shared-key: "win-x64-dev"', ci_rust_win_block)
        self.assertIn("save-if: ${{ github.ref == 'refs/heads/main' }}", ci_rust_win_block)
        self.assertIn(
            "cargo clippy --workspace --all-targets --locked -- -D warnings",
            ci_rust_win_block,
        )
        self.assertIn("cargo test --workspace --locked", ci_rust_win_block)
        self.assertIn("cargo doc --workspace --no-deps --locked", ci_rust_win_block)
        self.assertNotIn("cargo check", ci_rust_win_block)
        self.assertNotIn("-p ledr-daemon --test burst_budget", ci_rust_win_block)
        self.assertNotIn("-p ledr-store --test ttl_purge_lineage", ci_rust_win_block)

        # Unresolved suspended alert check in uninstall.ps1
        self.assertIn("--check-unresolved-suspended", uninstall_ps1)
        self.assertIn("Assert-NoUnresolvedSuspendedAlerts", uninstall_ps1)

        # Honeypot decoy automatic cleanup in uninstall.ps1 (L-06)
        self.assertIn("--cleanup-honeypots", uninstall_ps1)
        self.assertIn("Invoke-HoneypotCleanup", uninstall_ps1)
        stop_call_idx = uninstall_ps1.index("Wait-ForServiceStopped -Name $script:ServiceName")
        hp_call_idx = uninstall_ps1.index("Invoke-HoneypotCleanup -DaemonExePath $daemonExe")
        bin_del_idx = uninstall_ps1.index("$filesToDelete = @($script:BinaryNames)")
        self.assertLess(stop_call_idx, hp_call_idx)
        self.assertLess(hp_call_idx, bin_del_idx)

        runbook_md = (REPO_ROOT / "docs" / "release-runbook.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("honeypot_files", runbook_md)
        self.assertIn("--cleanup-honeypots", runbook_md)

        # Both scripts unwrap InnerException in Invoke-WithFileLockRetry
        self.assertIn(".InnerException", install_ps1)
        self.assertIn(".InnerException", uninstall_ps1)

    def test_rel_08b_extract_workflow_job_block_invariants(self) -> None:
        sample_lf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: windows-latest\n"
            "    steps:\n"
            "      - name: Build\n"
            "        with:\n"
            "          key: val\n"
            "    nested_key:\n"
            "      foo: bar\n"
            "  package:\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n"
            "      SECRET_MARKER: only-in-package\n"
            "  publish:\n"
            "    runs-on: ubuntu-latest\n"
        )
        sample_crlf = sample_lf.replace("\n", "\r\n")

        for sample in (sample_lf, sample_crlf):
            build_block = _extract_workflow_job_block(sample, "build")
            self.assertIn("runs-on: windows-latest", build_block)
            self.assertIn("nested_key:", build_block)
            self.assertNotIn("SECRET_MARKER", build_block)
            self.assertNotIn("runs-on: ubuntu-latest", build_block)

            publish_block = _extract_workflow_job_block(sample, "publish")
            self.assertIn("runs-on: ubuntu-latest", publish_block)
            self.assertNotIn("SECRET_MARKER", publish_block)

            with self.assertRaises(AssertionError):
                _extract_workflow_job_block(sample, "nonexistent")
            with self.assertRaises(AssertionError):
                _extract_workflow_job_block(sample, "steps")
            with self.assertRaises(AssertionError):
                _extract_workflow_job_block(sample, "nested_key")

    @unittest.skipUnless(
        sys.platform == "win32",
        "requires Windows PowerShell",
    )
    def test_rel_09_powershell_ast_and_retry_behavior(self) -> None:
        shells: list[tuple[str, str]] = []
        ps51 = shutil.which("powershell.exe")
        if ps51:
            shells.append(("powershell.exe", ps51))
        pwsh = shutil.which("pwsh") or shutil.which("pwsh.exe")
        if pwsh:
            shells.append(("pwsh", pwsh))
        self.assertTrue(
            shells,
            "Neither powershell.exe nor pwsh was found on Windows",
        )

        install_path = REPO_ROOT / "packaging" / "windows" / "install.ps1"
        uninstall_path = REPO_ROOT / "packaging" / "windows" / "uninstall.ps1"

        for shell_name, shell_exe in shells:
            with self.subTest(shell=shell_name):
                with tempfile.TemporaryDirectory() as tmp:
                    tmp_path = Path(tmp)
                    harness = tmp_path / "verify_ps_helpers.ps1"

                    harness.write_text(
                        rf"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

foreach ($p in @('{install_path}', '{uninstall_path}')) {{
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {{
        throw "Parse error(s) in $p`: $($errors | Out-String)"
    }}

    $retryFn = $ast.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-WithFileLockRetry' }}, $true) | Select-Object -First 1
    if ($null -eq $retryFn) {{
        throw "Invoke-WithFileLockRetry not found in $p"
    }}
    Invoke-Expression $retryFn.Extent.Text

    # 1. MethodInvocationException wrapping IOException must retry and succeed on 2nd attempt
    $script:attempts = 0
    Invoke-WithFileLockRetry -TimeoutSeconds 3 -Description "wrapped IOException retry ($p)" -Operation {{
        $script:attempts++
        if ($script:attempts -lt 2) {{
            [System.IO.File]::Delete((Join-Path '{tmp_path}' 'missing-dir\file.bin'))
        }}
    }}
    if ($script:attempts -ne 2) {{
        throw "Expected 2 attempts for wrapped IOException in $p, got $($script:attempts)"
    }}

    # 2. Non-IO exception must fail immediately without waiting for retry timeout
    $script:nonIoAttempts = 0
    $threw = $false
    try {{
        Invoke-WithFileLockRetry -TimeoutSeconds 5 -Description "non-IO fail fast ($p)" -Operation {{
            $script:nonIoAttempts++
            throw [System.ArgumentException]::new("bad arg")
        }}
    }}
    catch {{
        $threw = $true
    }}
    if ((-not $threw) -or ($script:nonIoAttempts -ne 1)) {{
        throw "Non-IO exception should fail immediately in 1 attempt in $p (threw=$threw, attempts=$($script:nonIoAttempts))"
    }}
}}

# Verify Invoke-IcaclsChecked from install.ps1 purges extraneous explicit ACEs and preserves target SIDs
$iTokens = $null
$iErrors = $null
$iAst = [System.Management.Automation.Language.Parser]::ParseFile('{install_path}', [ref]$iTokens, [ref]$iErrors)
foreach ($fnName in @('Ensure-NativeHelper', 'Invoke-NativeProcess', 'Invoke-IcaclsChecked')) {{
    $fnAst = $iAst.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $fnName }}, $true) | Select-Object -First 1
    if ($null -eq $fnAst) {{ throw "Missing function $fnName in install.ps1" }}
    Invoke-Expression $fnAst.Extent.Text
}}
$script:NativeHelperLoaded = $false

$aclTestDir = Join-Path '{tmp_path}' 'acl-hardening-test'
[void](New-Item -ItemType Directory -Path $aclTestDir -Force)
try {{
    $everyoneSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
    $authUsersSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')
    $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propFlags = [System.Security.AccessControl.PropagationFlags]::None

    $preAcl = Get-Acl -LiteralPath $aclTestDir
    $preAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($everyoneSid, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $inheritFlags, $propFlags, [System.Security.AccessControl.AccessControlType]::Allow)))
    $preAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($authUsersSid, [System.Security.AccessControl.FileSystemRights]::Modify, $inheritFlags, $propFlags, [System.Security.AccessControl.AccessControlType]::Allow)))
    Set-Acl -LiteralPath $aclTestDir -AclObject $preAcl

    $beforeExplicit = @((Get-Acl -LiteralPath $aclTestDir).GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {{ $_.IdentityReference.Value }})
    if (($beforeExplicit -notcontains 'S-1-1-0') -or ($beforeExplicit -notcontains 'S-1-5-11')) {{
        throw "Precondition failed: extraneous explicit ACEs were not added ($($beforeExplicit -join ','))"
    }}

    Invoke-IcaclsChecked -TargetPath $aclTestDir -GrantSpecs @('*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F')
    $afterAdminAcl = Get-Acl -LiteralPath $aclTestDir
    if (-not $afterAdminAcl.AreAccessRulesProtected) {{
        throw "Expected inheritance protection on $aclTestDir after Invoke-IcaclsChecked"
    }}
    $afterInherited = @($afterAdminAcl.GetAccessRules($false, $true, [System.Security.Principal.SecurityIdentifier]))
    if ($afterInherited.Count -ne 0) {{
        throw "Expected 0 inherited rules on $aclTestDir, got $($afterInherited.Count)"
    }}
    $afterAdminSids = (@($afterAdminAcl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {{ $_.IdentityReference.Value }} | Sort-Object -Unique)) -join ','
    if ($afterAdminSids -ne 'S-1-5-18,S-1-5-32-544') {{
        throw "Expected only SYSTEM and Administrators SIDs after admin hardening, got '$afterAdminSids'"
    }}

    # Re-add extraneous ACE and test InstallDir/NM-style grant with Users:RX
    $preAcl2 = Get-Acl -LiteralPath $aclTestDir
    $preAcl2.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($everyoneSid, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $inheritFlags, $propFlags, [System.Security.AccessControl.AccessControlType]::Allow)))
    Set-Acl -LiteralPath $aclTestDir -AclObject $preAcl2

    Invoke-IcaclsChecked -TargetPath $aclTestDir -GrantSpecs @('*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX')
    $afterUsersAcl = Get-Acl -LiteralPath $aclTestDir
    $afterUsersSids = (@($afterUsersAcl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {{ $_.IdentityReference.Value }} | Sort-Object -Unique)) -join ','
    if ($afterUsersSids -ne 'S-1-5-18,S-1-5-32-544,S-1-5-32-545') {{
        throw "Expected only SYSTEM, Administrators, and Users SIDs after Users:RX hardening, got '$afterUsersSids'"
    }}
}}
finally {{
    $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ((Test-Path -LiteralPath $aclTestDir) -and ($null -ne $currentUserSid)) {{
        try {{
            $cleanupAcl = Get-Acl -LiteralPath $aclTestDir
            $cleanupAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $currentUserSid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )))
            Set-Acl -LiteralPath $aclTestDir -AclObject $cleanupAcl
        }}
        catch {{
        }}
    }}
}}

# Verify Assert-NoUnresolvedSuspendedAlerts from uninstall.ps1 handles exit codes 0, 3, and 1
$tokens = $null
$errors = $null
$uAst = [System.Management.Automation.Language.Parser]::ParseFile('{uninstall_path}', [ref]$tokens, [ref]$errors)
foreach ($fnName in @('Write-UninstallLog', 'Normalize-FullPath', 'Assert-NoReparsePointComponent', 'Assert-NoUnresolvedSuspendedAlerts', 'Invoke-HoneypotCleanup')) {{
    $fnAst = $uAst.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $fnName }}, $true) | Select-Object -First 1
    if ($null -eq $fnAst) {{ throw "Missing function $fnName in uninstall.ps1" }}
    Invoke-Expression $fnAst.Extent.Text
}}
$script:LogWriter = $null
$script:LogBuffer = New-Object System.Collections.Generic.List[string]

$mockDb = Join-Path '{tmp_path}' 'localedr.db'
[System.IO.File]::WriteAllText($mockDb, 'mock')

$cmdZero = Join-Path '{tmp_path}' 'daemon_zero.cmd'
[System.IO.File]::WriteAllText($cmdZero, "@echo off`r`necho ok`r`nexit /b 0`r`n")
Assert-NoUnresolvedSuspendedAlerts -DaemonExePath $cmdZero -DbPath $mockDb

$cmdThree = Join-Path '{tmp_path}' 'daemon_three.cmd'
[System.IO.File]::WriteAllText($cmdThree, "@echo off`r`necho unresolved 1>&2`r`nexit /b 3`r`n")
$caught3 = $false
try {{
    Assert-NoUnresolvedSuspendedAlerts -DaemonExePath $cmdThree -DbPath $mockDb
}}
catch {{
    if ($_.Exception.Message -match 'ledr-ui\.exe') {{ $caught3 = $true }}
}}
if (-not $caught3) {{ throw "Expected exit code 3 to abort with ledr-ui.exe guidance" }}

$cmdOne = Join-Path '{tmp_path}' 'daemon_one.cmd'
[System.IO.File]::WriteAllText($cmdOne, "@echo off`r`necho db error 1>&2`r`nexit /b 1`r`n")
$caught1 = $false
try {{
    Assert-NoUnresolvedSuspendedAlerts -DaemonExePath $cmdOne -DbPath $mockDb
}}
catch {{
    if ($_.Exception.Message -match 'exit 1') {{ $caught1 = $true }}
}}
if (-not $caught1) {{ throw "Expected exit code 1 to fail closed" }}

# Verify Invoke-HoneypotCleanup handles exit 0, exit 4 (warn & continue), and missing binary
$script:LogBuffer.Clear()
$hpCmdZero = Join-Path '{tmp_path}' 'daemon_hp_zero.cmd'
[System.IO.File]::WriteAllText($hpCmdZero, "@echo off`r`necho Honeypot cleanup summary: removed=3`r`nexit /b 0`r`n")
Invoke-HoneypotCleanup -DaemonExePath $hpCmdZero -DbPath $mockDb -TimeoutSeconds 1
if (-not (@($script:LogBuffer | Where-Object {{ $_ -match '\[INFO\] Honeypot cleanup completed' }}).Count -eq 1)) {{
    throw "Expected INFO log on exit 0 from Invoke-HoneypotCleanup"
}}

$script:LogBuffer.Clear()
$hpCmdFourGuard = Join-Path '{tmp_path}' 'daemon_hp_four_guard.cmd'
[System.IO.File]::WriteAllText($hpCmdFourGuard, "@echo off`r`necho Honeypot cleanup failure: reparse point rejected 1>&2`r`nexit /b 4`r`n")
Invoke-HoneypotCleanup -DaemonExePath $hpCmdFourGuard -DbPath $mockDb -TimeoutSeconds 1
if (-not (@($script:LogBuffer | Where-Object {{ $_ -match '\[WARN\] Honeypot cleanup reported partial failure \(exit 4\)' }}).Count -eq 1)) {{
    throw "Expected WARN log on exit 4 guard rejection from Invoke-HoneypotCleanup"
}}

$script:LogBuffer.Clear()
$hpRetryFlag = Join-Path '{tmp_path}' 'hp_retry.flag'
$hpCmdRetry = Join-Path '{tmp_path}' 'daemon_hp_retry.cmd'
[System.IO.File]::WriteAllText($hpCmdRetry, "@echo off`r`nif exist `"$hpRetryFlag`" (`r`n  echo Honeypot cleanup summary: removed=1`r`n  exit /b 0`r`n)`r`necho retry> `"$hpRetryFlag`"`r`necho Honeypot cleanup failure: sharing violation 1>&2`r`nexit /b 4`r`n")
Invoke-HoneypotCleanup -DaemonExePath $hpCmdRetry -DbPath $mockDb -TimeoutSeconds 3
if (-not (Test-Path -LiteralPath $hpRetryFlag)) {{
    throw "Expected retry flag to be created on first attempt"
}}
if (-not (@($script:LogBuffer | Where-Object {{ $_ -match '\[INFO\] Honeypot cleanup completed' }}).Count -eq 1)) {{
    throw "Expected INFO log after retry succeeded"
}}

$script:LogBuffer.Clear()
$hpMissing = Join-Path '{tmp_path}' 'missing-daemon.exe'
Invoke-HoneypotCleanup -DaemonExePath $hpMissing -DbPath $mockDb -TimeoutSeconds 1
if (-not (@($script:LogBuffer | Where-Object {{ $_ -match '\[WARN\] Daemon binary not found' }}).Count -eq 1)) {{
    throw "Expected WARN log when daemon binary is missing"
}}
Write-Output "PS_VERIFY_OK"
""",
                        encoding="utf-8",
                    )
                    run_env = _sanitize_ps51_env() if shell_name == "powershell.exe" else None
                    res = subprocess.run(
                        [shell_exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(harness)],
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        env=run_env,
                        check=False,
                    )
                    self.assertEqual(
                        res.returncode,
                        0,
                        f"{shell_name} harness failed (rc={res.returncode}):\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}",
                    )
                    self.assertIn("PS_VERIFY_OK", res.stdout)

    def test_rel_10_powershell_polluted_psmodulepath_resilience(self) -> None:
        # 1. Cross-platform sanitizer unit check: drops PS 6/7 module dirs, preserves PS 5.1 dirs
        polluted_sample = {
            "SystemRoot": r"C:\Windows",
            "PSModulePath": ";".join(
                [
                    r"C:\Users\runneradmin\Documents\PowerShell\Modules",
                    r"C:\Program Files\PowerShell\Modules",
                    r"C:\Program Files\PowerShell\7\Modules",
                    r"C:\Program Files\PowerShell\7-preview\Modules",
                    r"C:\Program Files\WindowsPowerShell\Modules",
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules",
                ]
            ),
        }
        sanitized = _sanitize_ps51_env(polluted_sample)
        entries = sanitized["PSModulePath"].split(";")
        self.assertEqual(
            entries,
            [
                r"C:\Program Files\WindowsPowerShell\Modules",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules",
            ],
        )

        # Missing PSModulePath still populates WindowsPowerShell inbox Modules
        minimal = _sanitize_ps51_env({"SystemRoot": r"D:\Win"})
        self.assertEqual(
            minimal["PSModulePath"],
            r"D:\Win\System32\WindowsPowerShell\v1.0\Modules",
        )

        if sys.platform != "win32":
            return
        ps51 = shutil.which("powershell.exe")
        if not ps51:
            self.skipTest("powershell.exe not found on Windows")

        install_path = REPO_ROOT / "packaging" / "windows" / "install.ps1"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_sec_dir = (
                tmp_path
                / "PowerShell"
                / "7"
                / "Modules"
                / "Microsoft.PowerShell.Security"
            )
            fake_sec_dir.mkdir(parents=True)
            (fake_sec_dir / "Microsoft.PowerShell.Security.psd1").write_text(
                """@{
    ModuleVersion = '7.0.0.0'
    PowerShellVersion = '7.4'
    RootModule = 'Microsoft.PowerShell.Security.dll'
    CmdletsToExport = @('Get-Acl', 'Set-Acl')
}
""",
                encoding="utf-8",
            )
            acl_dir = tmp_path / "acl-target"
            acl_dir.mkdir()

            polluted_env = os.environ.copy()
            polluted_env["PSModulePath"] = ";".join(
                [str(fake_sec_dir.parent), polluted_env.get("PSModulePath", "")]
            )

            # Negative control: bare Get-Acl in powershell.exe under polluted PSModulePath must fail to autoload
            neg = subprocess.run(
                [
                    ps51,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    f"$ErrorActionPreference = 'Stop'; Get-Acl -LiteralPath '{acl_dir}' | Out-Null",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=polluted_env,
                check=False,
            )
            self.assertNotEqual(neg.returncode, 0)
            self.assertIn("CouldNotAutoloadMatchingModule", neg.stderr)

            # A. Sanitized PSModulePath allows bare Get-Acl in powershell.exe
            sanitized_env = _sanitize_ps51_env(polluted_env)
            pos_sanitized = subprocess.run(
                [
                    ps51,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    f"$ErrorActionPreference = 'Stop'; Get-Acl -LiteralPath '{acl_dir}' | Out-Null; Write-Output 'SANITIZED_PS51_OK'",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=sanitized_env,
                check=False,
            )
            self.assertEqual(
                pos_sanitized.returncode,
                0,
                f"Sanitized powershell.exe failed:\nSTDOUT:\n{pos_sanitized.stdout}\nSTDERR:\n{pos_sanitized.stderr}",
            )
            self.assertIn("SANITIZED_PS51_OK", pos_sanitized.stdout)

            # B. install.ps1's own Assert-AdminOrSystemOwnerIfExists and Invoke-IcaclsChecked
            #    must succeed in powershell.exe EVEN WITH polluted PSModulePath
            install_harness = tmp_path / "verify_install_polluted.ps1"
            install_harness.write_text(
                rf"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{install_path}', [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {{ throw "Parse error in install.ps1" }}
foreach ($fnName in @('Ensure-NativeHelper', 'Invoke-NativeProcess', 'Assert-AdminOrSystemOwnerIfExists', 'Invoke-IcaclsChecked')) {{
    $fnAst = $ast.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $fnName }}, $true) | Select-Object -First 1
    if ($null -eq $fnAst) {{ throw "Missing function $fnName in install.ps1" }}
    Invoke-Expression $fnAst.Extent.Text
}}
$script:NativeHelperLoaded = $false
Invoke-IcaclsChecked -TargetPath '{acl_dir}' -GrantSpecs @('*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F')
try {{
    Assert-AdminOrSystemOwnerIfExists -DirectoryPath '{acl_dir}'
}}
catch {{
    if ($_.Exception.Message -notmatch '^Unsafe owner SID ') {{
        throw
    }}
}}
Write-Output 'INSTALL_PS1_POLLUTED_OK'
""",
                encoding="utf-8",
            )
            try:
                pos_install = subprocess.run(
                    [
                        ps51,
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(install_harness),
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    env=polluted_env,
                    check=False,
                )
                self.assertEqual(
                    pos_install.returncode,
                    0,
                    f"install.ps1 helper failed under polluted PSModulePath:\nSTDOUT:\n{pos_install.stdout}\nSTDERR:\n{pos_install.stderr}",
                )
                self.assertIn("INSTALL_PS1_POLLUTED_OK", pos_install.stdout)
            finally:
                # Restore current user FullControl so TemporaryDirectory cleanup never hits AccessDenied
                subprocess.run(
                    [
                        ps51,
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-Command",
                        (
                            f"$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User; "
                            f"if ($null -ne $sid) {{ icacls.exe '{acl_dir}' /grant \"*$($sid.Value):(OI)(CI)F\" | Out-Null }}"
                        ),
                    ],
                    capture_output=True,
                    text=True,
                    env=sanitized_env,
                    check=False,
                )

            # C. Running install.ps1 entrypoint under polluted PSModulePath exercises top-level
            #    PSModulePath sanitization (for Microsoft.PowerShell.Management cmdlets such as
            #    Join-Path/Test-Path/Get-Item before Assert-NoReparsePointComponent) and
            #    Assert-AdminOrSystemOwnerIfExists (Get-Acl on existing_install), failing cleanly
            #    at the single error expected for existing_install's owner SID rather than module autoload.
            fake_mgmt_dir = fake_sec_dir.parent / "Microsoft.PowerShell.Management"
            fake_mgmt_dir.mkdir(parents=True)
            (fake_mgmt_dir / "Microsoft.PowerShell.Management.psd1").write_text(
                """@{
    ModuleVersion = '7.0.0.0'
    PowerShellVersion = '7.4'
    RootModule = 'Microsoft.PowerShell.Management.dll'
    CmdletsToExport = @('Test-Path', 'Get-Item', 'Join-Path')
}
""",
                encoding="utf-8",
            )
            neg_mgmt = subprocess.run(
                [
                    ps51,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    f"$ErrorActionPreference = 'Stop'; Test-Path -LiteralPath '{acl_dir}' | Out-Null",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=polluted_env,
                check=False,
            )
            self.assertNotEqual(neg_mgmt.returncode, 0)
            self.assertIn("CouldNotAutoloadMatchingModule", neg_mgmt.stderr)

            empty_src = tmp_path / "empty-src"
            empty_src.mkdir()
            existing_install = tmp_path / "existing-install"
            existing_install.mkdir()
            existing_install_ps = str(existing_install).replace("'", "''")
            owner_res = subprocess.run(
                [
                    ps51,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    (
                        "Set-StrictMode -Version Latest; "
                        "$ErrorActionPreference = 'Stop'; "
                        f"(Get-Acl -LiteralPath '{existing_install_ps}').GetOwner([System.Security.Principal.SecurityIdentifier]).Value"
                    ),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=_sanitize_ps51_env(),
                check=False,
            )
            self.assertEqual(
                owner_res.returncode,
                0,
                f"Failed to query owner SID for {existing_install}:\nSTDOUT:\n{owner_res.stdout}\nSTDERR:\n{owner_res.stderr}",
            )
            owner_sid = owner_res.stdout.strip()
            self.assertRegex(
                owner_sid,
                r"^S-1-(?:\d+|0x[0-9A-Fa-f]+)(?:-\d+)+$",
                f"Unexpected owner SID {owner_sid!r} for {existing_install}:\nSTDOUT:\n{owner_res.stdout}\nSTDERR:\n{owner_res.stderr}",
            )
            unused_data = tmp_path / "unused-data"
            ep_res = subprocess.run(
                [
                    ps51,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(install_path),
                    "-SourceDir",
                    str(empty_src),
                    "-InstallDir",
                    str(existing_install),
                    "-DataDir",
                    str(unused_data),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=polluted_env,
                check=False,
            )
            diag = (
                f"owner_sid={owner_sid}\nSTDOUT:\n{ep_res.stdout}\nSTDERR:\n{ep_res.stderr}"
            )
            self.assertNotEqual(ep_res.returncode, 0, diag)
            self.assertNotIn("CouldNotAutoloadMatchingModule", ep_res.stderr, diag)
            if owner_sid in ("S-1-5-32-544", "S-1-5-18"):
                self.assertIn("Missing required source binary", ep_res.stderr, diag)
                self.assertNotIn("Unsafe owner SID", ep_res.stderr, diag)
            else:
                self.assertIn(f"Unsafe owner SID '{owner_sid}'", ep_res.stderr, diag)
                self.assertNotIn("Missing required source binary", ep_res.stderr, diag)

    @unittest.skipUnless(
        sys.platform == "win32",
        "requires Windows PowerShell",
    )
    def test_rel_11_ensure_nsis_retry_fallback_and_fail_fast(self) -> None:
        release_yml = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        step_match = re.search(
            r"(?m)^      - name: Ensure NSIS \(makensis\) is installed\r?\n"
            r"        shell: pwsh\r?\n"
            r"        run: \|\r?\n"
            r"(?P<body>(?:          [^\n]*\r?\n|\r?\n)+?)"
            r"(?=^      - name: |\Z)",
            release_yml,
        )
        self.assertIsNotNone(
            step_match, "Could not extract Ensure NSIS step from release.yml"
        )
        step_script = textwrap.dedent(step_match.group("body")).strip() + "\n"
        self.assertIn("Resolve-MakeNsis", step_script)

        shells: list[tuple[str, str]] = []
        ps51 = shutil.which("powershell.exe")
        if ps51:
            shells.append(("powershell.exe", ps51))
        pwsh = shutil.which("pwsh") or shutil.which("pwsh.exe")
        if pwsh:
            shells.append(("pwsh", pwsh))
        self.assertTrue(
            shells,
            "Neither powershell.exe nor pwsh was found on Windows",
        )

        system_root = os.environ.get("SystemRoot", r"C:\Windows")

        for shell_name, shell_exe in shells:
            for scenario in (
                "winget_fallback",
                "fail_fast",
                "choco_retry_succeeds",
                "candidate_path_not_in_path",
            ):
                with self.subTest(shell=shell_name, scenario=scenario):
                    with tempfile.TemporaryDirectory() as tmp:
                        tmp_path = Path(tmp)
                        mock_bin = tmp_path / "mock_bin"
                        mock_bin.mkdir()
                        candidate_dir = tmp_path / "nsis_off_path"
                        candidate_exe = candidate_dir / "makensis.cmd"
                        script_path = tmp_path / "ensure_nsis.ps1"
                        script_path.write_text(step_script, encoding="utf-8")
                        github_path = tmp_path / "github_path.txt"
                        github_path.write_text("", encoding="utf-8")
                        choco_log = tmp_path / "choco.log"
                        winget_log = tmp_path / "winget.log"
                        flag_file = tmp_path / "choco_attempt1.flag"
                        makensis_cmd = mock_bin / "makensis.cmd"

                        def cmd_write_makensis(target: Path, ver_label: str) -> str:
                            return (
                                f'  (\r\n'
                                f'    echo @echo off\r\n'
                                f'    echo echo {ver_label}\r\n'
                                f'    echo exit /b 0\r\n'
                                f'  ) > "{target}"\r\n'
                            )

                        if scenario == "choco_retry_succeeds":
                            (mock_bin / "choco.cmd").write_text(
                                f'@echo off\r\n'
                                f'echo %*>> "{choco_log}"\r\n'
                                f'if exist "{flag_file}" (\r\n'
                                f'{cmd_write_makensis(makensis_cmd, "v3.13-mock")}'
                                f') else (\r\n'
                                f'  echo 1> "{flag_file}"\r\n'
                                f')\r\n'
                                f'exit /b 0\r\n',
                                encoding="utf-8",
                            )
                        elif scenario == "candidate_path_not_in_path":
                            (mock_bin / "choco.cmd").write_text(
                                f'@echo off\r\n'
                                f'echo %*>> "{choco_log}"\r\n'
                                f'if not exist "{candidate_dir}" mkdir "{candidate_dir}"\r\n'
                                f'{cmd_write_makensis(candidate_exe, "v3.13-offpath")}'
                                f'exit /b 0\r\n',
                                encoding="utf-8",
                            )
                        else:
                            (mock_bin / "choco.cmd").write_text(
                                f'@echo off\r\necho %*>> "{choco_log}"\r\nexit /b 0\r\n',
                                encoding="utf-8",
                            )

                        if scenario == "winget_fallback":
                            (mock_bin / "winget.cmd").write_text(
                                f'@echo off\r\n'
                                f'echo %*>> "{winget_log}"\r\n'
                                f'{cmd_write_makensis(makensis_cmd, "v3.13-mock")}'
                                f'exit /b 0\r\n',
                                encoding="utf-8",
                            )
                        else:
                            (mock_bin / "winget.cmd").write_text(
                                f'@echo off\r\necho %*>> "{winget_log}"\r\nexit /b 0\r\n',
                                encoding="utf-8",
                            )

                        env = os.environ.copy()
                        env["PATH"] = f"{mock_bin};{system_root}\\System32"
                        env["PATHEXT"] = ".COM;.EXE;.BAT;.CMD"
                        env["GITHUB_PATH"] = str(github_path)
                        if scenario == "candidate_path_not_in_path":
                            env["LEDR_NSIS_CANDIDATE_PATHS"] = (
                                f"{tmp_path / 'absent' / 'makensis.exe'};{candidate_exe}"
                            )
                        else:
                            env["LEDR_NSIS_CANDIDATE_PATHS"] = str(
                                tmp_path / "absent" / "makensis.exe"
                            )
                        env["LEDR_NSIS_RETRY_DELAY_SECONDS"] = "0"

                        res = subprocess.run(
                            [
                                shell_exe,
                                "-NoProfile",
                                "-ExecutionPolicy",
                                "Bypass",
                                "-File",
                                str(script_path),
                            ],
                            capture_output=True,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            env=env,
                            check=False,
                        )
                        diag = f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
                        choco_calls = (
                            choco_log.read_text(encoding="utf-8").splitlines()
                            if choco_log.exists()
                            else []
                        )
                        winget_calls = (
                            winget_log.read_text(encoding="utf-8").splitlines()
                            if winget_log.exists()
                            else []
                        )
                        github_path_lines = github_path.read_text(
                            encoding="utf-8"
                        ).splitlines()

                        if scenario == "winget_fallback":
                            self.assertEqual(res.returncode, 0, diag)
                            self.assertEqual(len(choco_calls), 3, diag)
                            self.assertEqual(len(winget_calls), 1, diag)
                            self.assertIn(str(mock_bin), github_path_lines, diag)
                            self.assertIn("Verified makensis at", res.stdout, diag)
                            self.assertIn("v3.13-mock", res.stdout, diag)
                        elif scenario == "fail_fast":
                            self.assertEqual(res.returncode, 1, diag)
                            self.assertEqual(len(choco_calls), 3, diag)
                            self.assertEqual(len(winget_calls), 1, diag)
                            self.assertIn(
                                "makensis.exe was not found",
                                res.stdout + res.stderr,
                                diag,
                            )
                        elif scenario == "candidate_path_not_in_path":
                            self.assertEqual(res.returncode, 0, diag)
                            self.assertEqual(len(choco_calls), 1, diag)
                            self.assertEqual(len(winget_calls), 0, diag)
                            self.assertIn(str(candidate_dir), github_path_lines, diag)
                            self.assertNotIn(str(mock_bin), github_path_lines, diag)
                            self.assertIn(
                                f"Verified makensis at {candidate_exe} (version v3.13-offpath)",
                                res.stdout,
                                diag,
                            )
                        else:
                            self.assertEqual(res.returncode, 0, diag)
                            self.assertEqual(len(choco_calls), 2, diag)
                            self.assertEqual(len(winget_calls), 0, diag)
                            self.assertIn("Verified makensis at", res.stdout, diag)
                            self.assertIn("v3.13-mock", res.stdout, diag)

    # REL-12: Release cache warmup workflow invariants (Phase R3-2)
    def test_rel_12_release_warmup_workflow_invariants(self) -> None:
        warmup_path = REPO_ROOT / ".github" / "workflows" / "release-warmup.yml"
        self.assertTrue(warmup_path.is_file(), "release-warmup.yml must exist")
        warmup_yml = warmup_path.read_text(encoding="utf-8")

        header_block = warmup_yml.split("\njobs:", 1)[0].split("\r\njobs:", 1)[0]
        header_active_lines = [
            re.sub(r"\s+#.*$", "", line)
            for line in header_block.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        header_active = "\n".join(header_active_lines)
        self.assertIn("name: Release Cache Warmup", header_active)
        self.assertIn("push:", header_active)
        self.assertIsNotNone(
            re.search(
                r"branches:[ \t]*(?:\[[ \t]*['\"]?main['\"]?[ \t]*\]|\r?\n[ \t]*-[ \t]*['\"]?main['\"]?[ \t]*(?:\r?\n(?![ \t]*-)|$))",
                header_active,
            ),
            "push trigger must target only main branch",
        )
        for path_glob in ("Cargo.toml", "**/Cargo.toml", "Cargo.lock", ".cargo/config.toml"):
            self.assertIsNotNone(
                re.search(
                    rf"^\s*-\s*['\"]?{re.escape(path_glob)}['\"]?\s*$",
                    header_active,
                    re.MULTILINE,
                ),
                f"push paths must include exact entry {path_glob!r}",
            )
        self.assertIn("schedule:", header_active)
        self.assertIn("0 3 */6 * *", header_active)
        self.assertIn("workflow_dispatch:", header_active)
        self.assertIn("permissions:", header_active)
        self.assertIn("contents: read", header_active)
        self.assertIn("concurrency:", header_active)
        self.assertIn("group: ${{ github.workflow }}-${{ github.ref }}", header_active)
        self.assertIn("cancel-in-progress: false", header_active)

        warmup_job = _extract_workflow_job_block(warmup_yml, "warmup")
        warmup_job_active = re.sub(r"(?m)^[ \t]*#.*$", "", warmup_job)
        self.assertIn("runs-on: windows-latest", warmup_job_active)
        self.assertIn("timeout-minutes: 25", warmup_job_active)
        self.assertIn("contents: read", warmup_job_active)
        self.assertIn("actions/checkout@v4", warmup_job_active)
        self.assertIn("dtolnay/rust-toolchain@stable", warmup_job_active)
        self.assertIsNone(
            re.search(
                r"uses:\s*dtolnay/rust-toolchain@stable(?:[ \t]*#[^\r\n]*)?\r?\n\s+with:",
                warmup_job_active,
            ),
            "dtolnay/rust-toolchain@stable must not define with: inputs so cache key matches release.yml build",
        )
        self.assertIn("Swatinem/rust-cache@v2", warmup_job_active)
        self.assertIn('shared-key: "win-x64-release"', warmup_job_active)
        self.assertIn("save-if: ${{ github.ref == 'refs/heads/main' }}", warmup_job_active)
        cache_on_failure_non_false = re.compile(
            r"""^[ \t]*(?:cache-on-failure|'cache-on-failure'|"cache-on-failure")[ \t]*:(?![ \t]*(?:false|'false'|"false")(?:[ \t]+#.*|[ \t]*)$)""",
            re.MULTILINE | re.IGNORECASE,
        )
        for tolerated_line in (
            "          cache-on-failure: false",
            "          cache-on-failure: 'false' # keep off",
            '          cache-on-failure: "FALSE"',
            "          cache-on-failure:false",
        ):
            self.assertIsNone(
                cache_on_failure_non_false.search(tolerated_line),
                f"cache_on_failure_non_false must tolerate {tolerated_line!r}",
            )
        for rejected_line in (
            "          cache-on-failure: true",
            "          cache-on-failure: 'true'",
            "          cache-on-failure: false_ish",
            "          cache-on-failure: ${{ env.FLAG }}",
            "          cache-on-failure: false# keep off",
            '          cache-on-failure: false"',
            "          cache-on-failure: 'false\"",
        ):
            self.assertIsNotNone(
                cache_on_failure_non_false.search(rejected_line),
                f"cache_on_failure_non_false must reject {rejected_line!r}",
            )
        self.assertIsNone(
            cache_on_failure_non_false.search(warmup_job_active),
            "warmup job must not enable cache-on-failure",
        )
        build_cmd = (
            "cargo build --release --locked -p ledr-daemon -p ledr-ui -p ledr-bridge-nm -p ledr-auth-helper"
        )
        self.assertIn(build_cmd, warmup_job_active)

        # Cross-check cache-key parity with release.yml build job (top-level & build job)
        release_yml = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        release_header = release_yml.split("\njobs:", 1)[0].split("\r\njobs:", 1)[0]
        rel_build_block = _extract_workflow_job_block(release_yml, "build")
        rel_build_active = re.sub(r"(?m)^[ \t]*#.*$", "", rel_build_block)
        self.assertIn("runs-on: windows-latest", rel_build_active)
        self.assertIn("dtolnay/rust-toolchain@stable", rel_build_active)
        self.assertIsNone(
            re.search(
                r"uses:\s*dtolnay/rust-toolchain@stable(?:[ \t]*#[^\r\n]*)?\r?\n\s+with:",
                rel_build_active,
            ),
            "release.yml build dtolnay/rust-toolchain@stable must not define with: inputs",
        )
        self.assertIn("Swatinem/rust-cache@v2", rel_build_active)
        self.assertIn('shared-key: "win-x64-release"', rel_build_active)
        self.assertIn("save-if: ${{ github.ref == 'refs/heads/main' }}", rel_build_active)
        self.assertIsNone(
            cache_on_failure_non_false.search(rel_build_active),
            "release.yml build must not enable cache-on-failure",
        )
        self.assertIn(build_cmd, rel_build_active)
        for label, scope_text in (
            ("release-warmup.yml", warmup_yml),
            ("release.yml header", release_header),
            ("release.yml build", rel_build_block),
        ):
            self.assertIsNone(
                re.search(
                    r"^[ \t]*['\"]?(?:CARGO_|RUST)[A-Z0-9_]*['\"]?[ \t]*:",
                    scope_text,
                    re.MULTILINE,
                ),
                f"{label} must not define extra CARGO_* or RUST* env vars that diverge cache keys",
            )

        # Security and cache-key isolation invariants
        self.assertNotIn("contents: write", warmup_yml)
        self.assertNotIn("LEDR_UPDATE_SIGNING_PRIVATE_KEY", warmup_yml)
        self.assertNotIn("LEDR_UPDATE_SIGNING_KEY_ID", warmup_yml)
        self.assertNotIn("secrets.", warmup_yml)
        self.assertNotIn("components: clippy", warmup_yml)
        self.assertNotIn("pull_request", warmup_yml)

        ci_yml = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        ci_gate_block = _extract_workflow_job_block(ci_yml, "ci-gate")
        self.assertNotIn("release-warmup", ci_gate_block)
        self.assertNotIn("warmup", ci_gate_block)
        self.assertNotIn("release-warmup", ci_yml)


if __name__ == "__main__":
    unittest.main()
