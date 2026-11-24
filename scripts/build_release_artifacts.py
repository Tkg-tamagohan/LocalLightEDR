#!/usr/bin/env python3
"""Deterministic release artifact builder for LocalEDR.

Packages the 6 release deliverables:
1. LocalEDR-Setup-vX.Y.Z-win-x64.exe
2. LocalEDR-vX.Y.Z-win-x64.zip
3. LocalEDR-chrome-ext-vX.Y.Z.zip
4. SHA256SUMS.txt
5. update-manifest.json
6. update-manifest.json.sig
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import zipfile

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import release_verify  # noqa: E402

FIXED_ZIP_DATE_TIME = (2026, 1, 1, 0, 0, 0)

PORTABLE_BINARIES = (
    "ledr-daemon.exe",
    "ledr-ui.exe",
    "ledr-bridge-nm.exe",
    "ledr-auth-helper.exe",
)

PORTABLE_RULES = (
    "lotl_core.json",
    "default_allowlist.json",
)

PORTABLE_SCRIPTS = (
    "install.ps1",
    "uninstall.ps1",
)

EXTENSION_STATIC_FILES = (
    "manifest.json",
    "background.js",
    "content.js",
    "content_main.js",
    "popup.html",
    "popup.js",
    "popup.css",
    "rules/dnr_static.json",
)


def _write_deterministic_zip(dest_zip: Path, file_pairs: list[tuple[str, Path]]) -> None:
    dest_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for arcname, src_path in sorted(file_pairs, key=lambda item: item[0]):
            if not src_path.is_file():
                raise ValueError(f"missing source file for {dest_zip.name}: {src_path}")
            info = zipfile.ZipInfo(filename=arcname, date_time=FIXED_ZIP_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, src_path.read_bytes())


def build_release_artifacts(
    *,
    repo_root: Path,
    bin_dir: Path,
    installer_exe: Path,
    out_dir: Path,
    public_keys_path: Path,
    key_id: str | None = None,
    private_key_file: Path | None = None,
    private_key_env: str = release_verify.DEFAULT_PRIVATE_KEY_ENV,
    min_updater_version: str = "0.1.0",
    released_at: str | None = None,
    expect_tag: str | None = None,
    skip_verify: bool = False,
) -> dict[str, str]:
    pre = release_verify.run_preflight(
        repo_root=repo_root,
        public_keys_path=public_keys_path,
        expect_tag=expect_tag,
        require_active_key=True,
    )
    version = pre["version"]
    tag = pre["tag"]

    release_verify.parse_semver_strict(min_updater_version)

    if not installer_exe.is_file():
        raise ValueError(f"installer executable not found: {installer_exe}")
    inst_size = installer_exe.stat().st_size
    if inst_size <= 0 or inst_size > release_verify.MAX_INSTALLER_BYTES:
        raise ValueError(
            f"installer executable size ({inst_size} bytes) outside 1..={release_verify.MAX_INSTALLER_BYTES}"
        )

    out_dir.mkdir(parents=True, exist_ok=True)

    setup_name = f"LocalEDR-Setup-v{version}-win-x64.exe"
    portable_name = f"LocalEDR-v{version}-win-x64.zip"
    ext_zip_name = f"LocalEDR-chrome-ext-v{version}.zip"

    setup_out = out_dir / setup_name
    portable_out = out_dir / portable_name
    ext_zip_out = out_dir / ext_zip_name
    sums_out = out_dir / "SHA256SUMS.txt"
    manifest_out = out_dir / "update-manifest.json"
    sig_out = out_dir / "update-manifest.json.sig"

    if installer_exe.resolve() != setup_out.resolve():
        shutil.copyfile(installer_exe, setup_out)

    # Build deterministic portable ZIP (never includes .pdb or non-distributed rules)
    portable_pairs: list[tuple[str, Path]] = []
    for binary in PORTABLE_BINARIES:
        portable_pairs.append((binary, bin_dir / binary))
    for rule_file in PORTABLE_RULES:
        portable_pairs.append((f"rules/{rule_file}", repo_root / "rules" / rule_file))
    for script_file in PORTABLE_SCRIPTS:
        portable_pairs.append((script_file, repo_root / "packaging" / "windows" / script_file))
    _write_deterministic_zip(portable_out, portable_pairs)

    # Build deterministic Chrome MV3 extension ZIP from explicit runtime allowlist
    ext_root = repo_root / "extensions" / "ledr-chrome-mv3"
    ext_pairs: list[tuple[str, Path]] = []
    for rel in EXTENSION_STATIC_FILES:
        ext_pairs.append((rel, ext_root / rel))
    lib_dir = ext_root / "lib"
    if not lib_dir.is_dir():
        raise ValueError(f"extension lib directory missing: {lib_dir}")
    for js_file in sorted(lib_dir.glob("*.js")):
        ext_pairs.append((f"lib/{js_file.name}", js_file))
    _write_deterministic_zip(ext_zip_out, ext_pairs)

    distributables = (setup_out, portable_out, ext_zip_out)
    checksum_lines = []
    hashes: dict[str, str] = {}
    for artifact in sorted(distributables, key=lambda p: p.name):
        digest = release_verify.sha256_file(artifact)
        hashes[artifact.name] = digest
        checksum_lines.append(f"{digest}  {artifact.name}")
    sums_out.write_bytes(("\n".join(checksum_lines) + "\n").encode("utf-8"))

    ts_utc = released_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest_doc = {
        "schema_version": release_verify.MANIFEST_SCHEMA_VERSION,
        "product": release_verify.EXPECTED_PRODUCT_NAME,
        "version": version,
        "tag": tag,
        "released_at": ts_utc,
        "min_updater_version": min_updater_version,
        "filename": setup_name,
        "download_url": f"{release_verify.RELEASE_URL_PREFIX}download/{tag}/{setup_name}",
        "sha256": hashes[setup_name],
        "size_bytes": setup_out.stat().st_size,
        "release_notes_url": f"{release_verify.RELEASE_URL_PREFIX}tag/{tag}",
        "chrome_extension": {
            "extension_id": release_verify.EXPECTED_CHROME_EXTENSION_ID,
            "version": version,
            "download_url": f"{release_verify.RELEASE_URL_PREFIX}download/{tag}/{ext_zip_name}",
            "sha256": hashes[ext_zip_name],
        },
    }
    manifest_bytes = (json.dumps(manifest_doc, indent=2) + "\n").encode("utf-8")
    manifest_out.write_bytes(manifest_bytes)

    release_verify.sign_manifest_file(
        manifest_path=manifest_out,
        out_sig_path=sig_out,
        public_keys_path=public_keys_path,
        key_id=key_id,
        private_key_file=private_key_file,
        private_key_env=private_key_env,
    )

    if not skip_verify:
        release_verify.verify_dist(
            dist_dir=out_dir,
            public_keys_path=public_keys_path,
            expect_tag=tag,
            expect_version=version,
        )

    return {
        "version": version,
        "tag": tag,
        "setup_exe": str(setup_out),
        "portable_zip": str(portable_out),
        "chrome_ext_zip": str(ext_zip_out),
        "sha256sums": str(sums_out),
        "manifest": str(manifest_out),
        "signature": str(sig_out),
    }


def build_parser() -> argparse.ArgumentParser:
    repo_default = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Build and sign LocalEDR release artifacts")
    parser.add_argument("--repo-root", type=Path, default=repo_default)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--installer-exe", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--public-keys",
        type=Path,
        default=repo_default / "packaging" / "update-public-keys.json",
    )
    parser.add_argument("--key-id", default=None)
    parser.add_argument("--private-key-file", type=Path, default=None)
    parser.add_argument("--private-key-env", default=release_verify.DEFAULT_PRIVATE_KEY_ENV)
    parser.add_argument("--min-updater-version", default="0.1.0")
    parser.add_argument("--released-at", default=None)
    parser.add_argument("--expect-tag", default=None)
    parser.add_argument("--skip-verify", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        res = build_release_artifacts(
            repo_root=args.repo_root,
            bin_dir=args.bin_dir,
            installer_exe=args.installer_exe,
            out_dir=args.out_dir,
            public_keys_path=args.public_keys,
            key_id=args.key_id,
            private_key_file=args.private_key_file,
            private_key_env=args.private_key_env,
            min_updater_version=args.min_updater_version,
            released_at=args.released_at,
            expect_tag=args.expect_tag,
            skip_verify=args.skip_verify,
        )
        print(
            f"Built and verified 6 release artifacts for {res['tag']} in {args.out_dir}"
        )
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
