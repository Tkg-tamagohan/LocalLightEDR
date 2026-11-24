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
import unittest
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import build_release_artifacts  # noqa: E402
import release_verify  # noqa: E402


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
            require_active_key=False,
        )
        self.assertEqual(real_res["version"], "0.1.0")
        self.assertEqual(real_res["extension_id"], release_verify.EXPECTED_CHROME_EXTENSION_ID)

        with self.assertRaises(ValueError):
            release_verify.run_preflight(
                repo_root=REPO_ROOT,
                public_keys_path=REPO_ROOT / "packaging" / "update-public-keys.json",
                expect_tag="v9.9.9",
            )
        with self.assertRaises(ValueError):
            release_verify.run_preflight(
                repo_root=REPO_ROOT,
                public_keys_path=REPO_ROOT / "packaging" / "update-public-keys.json",
                require_active_key=True,
            )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _, _, pub_keys = _create_mock_repo(tmp_path, "0.2.0")
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
        # Checkout ref pinning across preflight, build, publish
        self.assertGreaterEqual(len(re.findall(r"uses:\s*actions/checkout@v4", release_yml)), 3)
        self.assertIn("ref: ${{ github.sha }}", release_yml)
        self.assertEqual(
            release_yml.count("ref: ${{ needs.preflight.outputs.source_sha }}"), 2
        )
        # Non-dry-run tag commit verification & --verify-tag
        self.assertIn('refs/tags/${RELEASE_TAG}^{commit}', release_yml)
        self.assertIn('refs/tags/${TAG}^{commit}', release_yml)
        self.assertIn("--verify-tag", release_yml)
        # Dry-run key-id override
        self.assertIn("--key-id dry-run-test", release_yml)

        install_ps1 = (REPO_ROOT / "packaging" / "windows" / "install.ps1").read_text(
            encoding="utf-8"
        )
        uninstall_ps1 = (REPO_ROOT / "packaging" / "windows" / "uninstall.ps1").read_text(
            encoding="utf-8"
        )

        # Rollback preservation & ACL hardening markers in install.ps1
        self.assertIn("$rollbackRestoreFailed", install_ps1)
        self.assertIn("PurgeAccessRules", install_ps1)
        self.assertIn("SetAccessRuleProtection($true, $false)", install_ps1)
        self.assertIn("Reset-DataSubdirInheritedAcl", install_ps1)

        # Unresolved suspended alert check in uninstall.ps1
        self.assertIn("--check-unresolved-suspended", uninstall_ps1)
        self.assertIn("Assert-NoUnresolvedSuspendedAlerts", uninstall_ps1)

        # Both scripts unwrap InnerException in Invoke-WithFileLockRetry
        self.assertIn(".InnerException", install_ps1)
        self.assertIn(".InnerException", uninstall_ps1)

    @unittest.skipUnless(
        sys.platform == "win32" and shutil.which("powershell.exe") is not None,
        "requires Windows PowerShell",
    )
    def test_rel_09_powershell_ast_and_retry_behavior(self) -> None:
        ps_exe = shutil.which("powershell.exe")
        assert ps_exe is not None

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            harness = tmp_path / "verify_ps_helpers.ps1"
            install_path = REPO_ROOT / "packaging" / "windows" / "install.ps1"
            uninstall_path = REPO_ROOT / "packaging" / "windows" / "uninstall.ps1"

            harness.write_text(
                f"""
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
    $missingPath = Join-Path '{tmp_path}' 'nonexistent-file-for-retry-test.bin'
    Invoke-WithFileLockRetry -TimeoutSeconds 3 -Description "wrapped IOException retry ($p)" -Operation {{
        $script:attempts++
        if ($script:attempts -lt 2) {{
            [System.IO.File]::Delete((Join-Path '{tmp_path}' 'missing-dir\\file.bin'))
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

# Verify Assert-NoUnresolvedSuspendedAlerts from uninstall.ps1 handles exit codes 0, 3, and 1
$tokens = $null
$errors = $null
$uAst = [System.Management.Automation.Language.Parser]::ParseFile('{uninstall_path}', [ref]$tokens, [ref]$errors)
foreach ($fnName in @('Write-UninstallLog', 'Normalize-FullPath', 'Assert-NoReparsePointComponent', 'Assert-NoUnresolvedSuspendedAlerts')) {{
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
Write-Output "PS_VERIFY_OK"
""",
                encoding="utf-8",
            )
            res = subprocess.run(
                [ps_exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(harness)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            self.assertEqual(
                res.returncode,
                0,
                f"PowerShell harness failed (rc={res.returncode}):\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}",
            )
            self.assertIn("PS_VERIFY_OK", res.stdout)


if __name__ == "__main__":
    unittest.main()
