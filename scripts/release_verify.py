#!/usr/bin/env python3
"""Release preflight, Ed25519 manifest signing, and distribution verification.

Uses only the Python 3.11+ standard library (zero external dependencies) and
implements strict RFC 8032 Ed25519 compatible with ``ed25519-dalek`` 2.2.0.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tomllib
from typing import Any
from urllib.parse import urlparse
import zipfile

# Normative constants synchronized with crates/ledr-updater/src/lib.rs
RELEASE_URL_PREFIX = "https://github.com/Tkg-tamagohan/LocalLightEDR/releases/"
ALLOWED_DOWNLOAD_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com",
    }
)
EXPECTED_PRODUCT_NAME = "LocalEDR"
EXPECTED_CHROME_EXTENSION_ID = "ecelachfiiiiiibpjeomfncgpegbpanh"
KEY_RING_SCHEMA_VERSION = 1
MANIFEST_SCHEMA_VERSION = 1
SIGNATURE_SCHEMA_VERSION = 1
SIGNATURE_ALGORITHM_ED25519 = "ed25519"
ALLOWED_KEY_STATUSES = frozenset({"active", "disabled", "revoked"})

MAX_MANIFEST_BYTES = 64 * 1024
MAX_SIG_BYTES = 4 * 1024
MAX_INSTALLER_BYTES = 128 * 1024 * 1024

DEFAULT_PRIVATE_KEY_ENV = "LEDR_UPDATE_SIGNING_PRIVATE_KEY"
DEFAULT_KEY_ID_ENV = "LEDR_UPDATE_SIGNING_KEY_ID"

PKCS8_ED25519_V1_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
PKCS8_ED25519_V2_PREFIX = bytes.fromhex("3053020101300506032b657004220420")

SEMVER_NUM_RE = re.compile(r"^(0|[1-9][0-9]*)$")
SEMVER_PRE_PART_RE = re.compile(r"^[0-9A-Za-z-]+$")
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_PORTABLE_ZIP_FILES = frozenset(
    {
        "ledr-daemon.exe",
        "ledr-ui.exe",
        "ledr-bridge-nm.exe",
        "ledr-auth-helper.exe",
        "rules/lotl_core.json",
        "rules/default_allowlist.json",
        "install.ps1",
        "uninstall.ps1",
    }
)

REQUIRED_EXTENSION_ZIP_FILES = frozenset(
    {
        "manifest.json",
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
    }
)

FORBIDDEN_ARCHIVE_SEGMENTS = frozenset(
    {"_metadata", "tests", "node_modules", "__pycache__", ".git"}
)

# ---------------------------------------------------------------------------
# Pure-Python RFC 8032 Ed25519 (strict verification matching ed25519-dalek)
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> int:
    if y >= _P:
        raise ValueError("non-canonical y coordinate")
    y2 = (y * y) % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    v3 = pow(v, 3, _P)
    v7 = (v3 * v3 * v) % _P
    x = (u * v3 * pow((u * v7) % _P, (_P - 5) // 8, _P)) % _P
    check = (v * x * x) % _P
    if check != u:
        x = (x * _I) % _P
        if (v * x * x) % _P != u:
            raise ValueError("point is not on Ed25519 curve")
    if x == 0 and sign == 1:
        raise ValueError("non-canonical zero x with sign bit")
    if (x & 1) != sign:
        x = _P - x
    return x


_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = _recover_x(_BY, 0)
_B_EXT = (_BX, _BY, 1, (_BX * _BY) % _P)


def _point_add(
    p: tuple[int, int, int, int], q: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * _D * t1 * t2) % _P
    d = (2 * z1 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return (
        (e * f) % _P,
        (g * h) % _P,
        (f * g) % _P,
        (e * h) % _P,
    )


def _point_mul(s: int, p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    r = _IDENTITY
    acc = p
    k = s
    while k > 0:
        if k & 1:
            r = _point_add(r, acc)
        acc = _point_add(acc, acc)
        k >>= 1
    return r


def _point_equal(
    p: tuple[int, int, int, int], q: tuple[int, int, int, int]
) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _is_small_order(p: tuple[int, int, int, int]) -> bool:
    return _point_equal(_point_mul(8, p), _IDENTITY)


def _point_compress(p: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = p
    z_inv = pow(z, _P - 2, _P)
    rx = (x * z_inv) % _P
    ry = (y * z_inv) % _P
    val = ry | ((rx & 1) << 255)
    return val.to_bytes(32, "little")


def _point_decompress(data: bytes) -> tuple[int, int, int, int]:
    if len(data) != 32:
        raise ValueError("compressed point must be 32 bytes")
    raw = int.from_bytes(data, "little")
    y = raw & ((1 << 255) - 1)
    sign = (raw >> 255) & 1
    x = _recover_x(y, sign)
    return (x, y, 1, (x * y) % _P)


def _clamp_scalar(digest_low32: bytes) -> int:
    buf = bytearray(digest_low32)
    buf[0] &= 248
    buf[31] &= 127
    buf[31] |= 64
    return int.from_bytes(buf, "little")


def ed25519_pubkey_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = _clamp_scalar(h[:32])
    return _point_compress(_point_mul(a, _B_EXT))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = _clamp_scalar(h[:32])
    prefix = h[32:]
    pub = _point_compress(_point_mul(a, _B_EXT))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    r_pt = _point_mul(r, _B_EXT)
    r_bytes = _point_compress(r_pt)
    k = int.from_bytes(hashlib.sha512(r_bytes + pub + message).digest(), "little") % _L
    s = (r + k * a) % _L
    return r_bytes + s.to_bytes(32, "little")


def ed25519_verify_strict(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    if len(pubkey) != 32 or len(signature) != 64:
        return False
    try:
        a_pt = _point_decompress(pubkey)
        if _is_small_order(a_pt):
            return False
        r_bytes = signature[:32]
        s_val = int.from_bytes(signature[32:], "little")
        if s_val >= _L:
            return False
        r_pt = _point_decompress(r_bytes)
        if _is_small_order(r_pt):
            return False
    except ValueError:
        return False

    k = int.from_bytes(hashlib.sha512(r_bytes + pubkey + message).digest(), "little") % _L
    lhs = _point_mul(s_val, _B_EXT)
    rhs = _point_add(r_pt, _point_mul(k, a_pt))
    return _point_equal(lhs, rhs)


# ---------------------------------------------------------------------------
# Strict Base64, SemVer, Key Parsing, and Schema Validators
# ---------------------------------------------------------------------------


def decode_base64_strict(text: str) -> bytes:
    if not isinstance(text, str) or not text or any(ch.isspace() for ch in text):
        raise ValueError("Base64 value must be a non-empty string without whitespace")
    if len(text) % 4 != 0:
        raise ValueError("Base64 value must be padded to a multiple of 4 characters")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid Base64 encoding: {exc}") from exc
    if base64.b64encode(raw).decode("ascii") != text:
        raise ValueError("non-canonical Base64 encoding")
    return raw


def encode_pkcs8_pem_from_seed(seed: bytes) -> str:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    der = PKCS8_ED25519_V1_PREFIX + seed
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END PRIVATE KEY-----\n"


def parse_ed25519_private_seed(raw_text: str) -> bytes:
    """Parses 32-byte Base64 seed, 64-byte Base64 seed+pub, or PKCS#8 PEM.

    Never echoes private material in raised exception messages.
    """
    if not isinstance(raw_text, str):
        raise ValueError("private key input must be text")
    stripped = raw_text.strip()
    if not stripped:
        raise ValueError("private key input is empty")

    if "-----BEGIN PRIVATE KEY-----" in stripped:
        m = re.search(
            r"-----BEGIN PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END PRIVATE KEY-----",
            stripped,
        )
        if not m:
            raise ValueError("malformed PKCS#8 PEM private key block")
        b64_compact = re.sub(r"\s+", "", m.group(1))
        try:
            der = base64.b64decode(b64_compact, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("invalid Base64 inside PKCS#8 PEM") from exc
        if len(der) == 48 and der.startswith(PKCS8_ED25519_V1_PREFIX):
            return der[len(PKCS8_ED25519_V1_PREFIX) :]
        if len(der) >= len(PKCS8_ED25519_V2_PREFIX) + 32 and der.startswith(PKCS8_ED25519_V2_PREFIX):
            return der[len(PKCS8_ED25519_V2_PREFIX) : len(PKCS8_ED25519_V2_PREFIX) + 32]
        raise ValueError("unsupported PKCS#8 Ed25519 DER structure")

    try:
        raw = decode_base64_strict(stripped)
    except ValueError as exc:
        raise ValueError("invalid Base64 Ed25519 private key") from exc

    if len(raw) == 32:
        return raw
    if len(raw) == 64:
        seed = raw[:32]
        embedded_pub = raw[32:]
        if ed25519_pubkey_from_seed(seed) != embedded_pub:
            raise ValueError("64-byte Ed25519 private key has mismatched embedded public key")
        return seed
    raise ValueError(f"unsupported Ed25519 private key length ({len(raw)} bytes; expected 32 or 64)")


def parse_semver_strict(version_str: str) -> tuple[int, int, int, str | None]:
    if not isinstance(version_str, str) or not version_str:
        raise ValueError("version must be a non-empty string")
    if version_str.startswith("v") or "+" in version_str or any(c.isspace() for c in version_str):
        raise ValueError(f"invalid strict SemVer '{version_str}'")
    core, sep, pre = version_str.partition("-")
    parts = core.split(".")
    if len(parts) != 3:
        raise ValueError(f"SemVer '{version_str}' must have MAJOR.MINOR.PATCH")
    nums: list[int] = []
    for part in parts:
        if not SEMVER_NUM_RE.match(part):
            raise ValueError(f"invalid SemVer numeric component '{part}' in '{version_str}'")
        nums.append(int(part))
    pre_val: str | None = None
    if sep:
        if not pre:
            raise ValueError(f"empty prerelease tag in '{version_str}'")
        for ident in pre.split("."):
            if not ident or not SEMVER_PRE_PART_RE.match(ident):
                raise ValueError(f"invalid prerelease identifier '{ident}' in '{version_str}'")
            if ident.isdigit() and len(ident) > 1 and ident.startswith("0"):
                raise ValueError(f"leading zero in numeric prerelease identifier '{ident}'")
        pre_val = pre
    return (nums[0], nums[1], nums[2], pre_val)


def compare_semver(a: tuple[int, int, int, str | None], b: tuple[int, int, int, str | None]) -> int:
    core_a, core_b = a[:3], b[:3]
    if core_a < core_b:
        return -1
    if core_a > core_b:
        return 1
    pre_a, pre_b = a[3], b[3]
    if pre_a is None and pre_b is None:
        return 0
    if pre_a is None:
        return 1
    if pre_b is None:
        return -1
    if pre_a < pre_b:
        return -1
    if pre_a > pre_b:
        return 1
    return 0


def derive_chrome_extension_id(public_key_b64: str) -> str:
    der = decode_base64_strict(public_key_b64)
    digest = hashlib.sha256(der).digest()[:16]
    return "".join(chr(97 + (b >> 4)) + chr(97 + (b & 0x0F)) for b in digest)


def validate_single_segment_filename(filename: str) -> None:
    if not isinstance(filename, str) or not filename:
        raise ValueError("manifest filename must be non-empty")
    if (
        filename in {".", ".."}
        or ".." in filename
        or "/" in filename
        or "\\" in filename
        or ":" in filename
        or "\x00" in filename
    ):
        raise ValueError(f"unsafe manifest filename '{filename}'")


def validate_download_url(url: str) -> None:
    if not isinstance(url, str) or not url:
        raise ValueError("download_url must be non-empty")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"download_url must use https: '{url}'")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_DOWNLOAD_HOSTS:
        raise ValueError(f"download_url host '{host}' is not in ALLOWED_DOWNLOAD_HOSTS")


def load_json_strict(path: Path) -> Any:
    def _reject_const(token: str) -> None:
        raise ValueError(f"non-standard JSON constant {token!r}")

    return json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_const)


def parse_public_key_ring(path: Path, *, require_active_key: bool) -> dict[str, bytes]:
    if not path.is_file():
        raise ValueError(f"public keys file not found: {path}")
    data = load_json_strict(path)
    if not isinstance(data, dict):
        raise ValueError("update-public-keys.json root must be an object")
    if data.get("schema_version") != KEY_RING_SCHEMA_VERSION:
        raise ValueError(
            f"update-public-keys.json schema_version must be {KEY_RING_SCHEMA_VERSION}"
        )
    keys = data.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("update-public-keys.json 'keys' must be a non-empty array")

    seen_ids: set[str] = set()
    active_keys: dict[str, bytes] = {}
    for entry in keys:
        if not isinstance(entry, dict):
            raise ValueError("public key entry must be an object")
        key_id = entry.get("key_id")
        pub_b64 = entry.get("public_key_b64")
        status = entry.get("status")
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("public key entry missing non-empty 'key_id'")
        if key_id in seen_ids:
            raise ValueError(f"duplicate key_id in update-public-keys.json: '{key_id}'")
        seen_ids.add(key_id)
        if status not in ALLOWED_KEY_STATUSES:
            raise ValueError(f"invalid status '{status}' for key_id '{key_id}'")
        if not isinstance(pub_b64, str) or not pub_b64:
            raise ValueError(f"missing public_key_b64 for key_id '{key_id}'")

        if status == "active":
            if pub_b64 == "UNCONFIGURED_PLACEHOLDER":
                raise ValueError(f"active key '{key_id}' cannot use placeholder value")
            pub_bytes = decode_base64_strict(pub_b64)
            if len(pub_bytes) != 32:
                raise ValueError(f"active key '{key_id}' must decode to 32 bytes")
            pt = _point_decompress(pub_bytes)
            if _is_small_order(pt):
                raise ValueError(f"active key '{key_id}' is a small-order Ed25519 point")
            active_keys[key_id] = pub_bytes

    if require_active_key and not active_keys:
        raise ValueError("no active signing keys configured in update-public-keys.json")

    return active_keys


def read_synced_versions(repo_root: Path) -> str:
    cargo_path = repo_root / "Cargo.toml"
    tauri_path = repo_root / "apps" / "ledr-ui" / "tauri.conf.json"
    ext_path = repo_root / "extensions" / "ledr-chrome-mv3" / "manifest.json"

    for p in (cargo_path, tauri_path, ext_path):
        if not p.is_file():
            raise ValueError(f"required version file missing: {p}")

    cargo_data = tomllib.loads(cargo_path.read_text(encoding="utf-8"))
    cargo_ver = cargo_data.get("workspace", {}).get("package", {}).get("version")
    tauri_ver = load_json_strict(tauri_path).get("version")
    ext_manifest = load_json_strict(ext_path)
    ext_ver = ext_manifest.get("version")

    for label, ver in (
        ("Cargo.toml", cargo_ver),
        ("apps/ledr-ui/tauri.conf.json", tauri_ver),
        ("extensions/ledr-chrome-mv3/manifest.json", ext_ver),
    ):
        parsed = parse_semver_strict(str(ver or ""))
        if parsed[3] is not None:
            raise ValueError(f"{label} version '{ver}' must not be a prerelease")

    if not (cargo_ver == tauri_ver == ext_ver):
        raise ValueError(
            f"version mismatch across repo files: Cargo.toml={cargo_ver!r}, "
            f"tauri.conf.json={tauri_ver!r}, manifest.json={ext_ver!r}"
        )

    ext_key = ext_manifest.get("key")
    if not isinstance(ext_key, str) or not ext_key:
        raise ValueError("extensions/ledr-chrome-mv3/manifest.json is missing 'key'")
    derived_id = derive_chrome_extension_id(ext_key)
    if derived_id != EXPECTED_CHROME_EXTENSION_ID:
        raise ValueError(
            f"Chrome extension ID mismatch: expected {EXPECTED_CHROME_EXTENSION_ID}, derived {derived_id}"
        )

    return str(cargo_ver)


def load_private_seed_from_args(
    *,
    private_key_file: Path | None,
    private_key_env: str,
) -> bytes:
    if private_key_file is not None:
        if not private_key_file.is_file():
            raise ValueError(f"private key file not found: {private_key_file}")
        return parse_ed25519_private_seed(private_key_file.read_text(encoding="utf-8"))
    raw_env = os.environ.get(private_key_env, "")
    if not raw_env.strip():
        raise ValueError(f"signing private key environment variable '{private_key_env}' is not set")
    return parse_ed25519_private_seed(raw_env)


def resolve_signing_key_id(
    active_keys: dict[str, bytes],
    derived_pubkey: bytes,
    requested_key_id: str | None,
) -> str:
    if requested_key_id:
        if requested_key_id not in active_keys:
            raise ValueError(f"key_id '{requested_key_id}' is not an active key in update-public-keys.json")
        if active_keys[requested_key_id] != derived_pubkey:
            raise ValueError(f"private key does not match public key for key_id '{requested_key_id}'")
        return requested_key_id

    matches = [kid for kid, pub in active_keys.items() if pub == derived_pubkey]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ValueError("private key does not match any active key in update-public-keys.json")
    raise ValueError("multiple active key_ids share this public key; pass --key-id explicitly")


def validate_manifest_structure(
    manifest_bytes: bytes,
    *,
    expect_version: str | None = None,
) -> dict[str, Any]:
    if len(manifest_bytes) == 0 or len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise ValueError(
            f"update-manifest.json size ({len(manifest_bytes)} bytes) outside 1..={MAX_MANIFEST_BYTES}"
        )
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"invalid update-manifest.json UTF-8/JSON: {exc}") from exc

    if not isinstance(manifest, dict):
        raise ValueError("update-manifest.json must be a JSON object")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValueError(f"manifest schema_version must be {MANIFEST_SCHEMA_VERSION}")
    if manifest.get("product") != EXPECTED_PRODUCT_NAME:
        raise ValueError(f"manifest product must be '{EXPECTED_PRODUCT_NAME}'")

    version = manifest.get("version")
    parsed_ver = parse_semver_strict(str(version or ""))
    if parsed_ver[3] is not None:
        raise ValueError(f"manifest version '{version}' must not be a prerelease")
    if expect_version is not None and version != expect_version:
        raise ValueError(f"manifest version '{version}' != expected '{expect_version}'")

    expected_tag = f"v{version}"
    if manifest.get("tag") != expected_tag:
        raise ValueError(f"manifest tag '{manifest.get('tag')}' != expected '{expected_tag}'")

    min_ver_raw = manifest.get("min_updater_version")
    parsed_min = parse_semver_strict(str(min_ver_raw or ""))
    if compare_semver(parsed_min, parsed_ver) > 0:
        raise ValueError(
            f"min_updater_version '{min_ver_raw}' cannot exceed manifest version '{version}'"
        )

    filename = manifest.get("filename")
    validate_single_segment_filename(str(filename or ""))
    expected_filename = f"LocalEDR-Setup-v{version}-win-x64.exe"
    if filename != expected_filename:
        raise ValueError(f"manifest filename '{filename}' != expected '{expected_filename}'")

    download_url = str(manifest.get("download_url") or "")
    validate_download_url(download_url)
    expected_dl = f"{RELEASE_URL_PREFIX}download/{expected_tag}/{expected_filename}"
    if download_url != expected_dl:
        raise ValueError(f"manifest download_url '{download_url}' != expected '{expected_dl}'")

    sha256_val = manifest.get("sha256")
    if not isinstance(sha256_val, str) or not SHA256_HEX_RE.match(sha256_val):
        raise ValueError("manifest sha256 must be 64 lowercase hex chars")

    size_bytes = manifest.get("size_bytes")
    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes <= 0 or size_bytes > MAX_INSTALLER_BYTES:
        raise ValueError(f"manifest size_bytes '{size_bytes}' out of range")

    notes_url = manifest.get("release_notes_url")
    if not isinstance(notes_url, str) or not notes_url.startswith(RELEASE_URL_PREFIX):
        raise ValueError(f"manifest release_notes_url must start with '{RELEASE_URL_PREFIX}'")

    ext_info = manifest.get("chrome_extension")
    if not isinstance(ext_info, dict):
        raise ValueError("manifest missing 'chrome_extension' object")
    if ext_info.get("extension_id") != EXPECTED_CHROME_EXTENSION_ID:
        raise ValueError(
            f"chrome_extension.extension_id must be '{EXPECTED_CHROME_EXTENSION_ID}'"
        )
    if ext_info.get("version") != version:
        raise ValueError(f"chrome_extension.version '{ext_info.get('version')}' != '{version}'")
    ext_dl = ext_info.get("download_url")
    expected_ext_dl = f"{RELEASE_URL_PREFIX}download/{expected_tag}/LocalEDR-chrome-ext-v{version}.zip"
    if ext_dl != expected_ext_dl:
        raise ValueError(f"chrome_extension.download_url '{ext_dl}' != '{expected_ext_dl}'")
    ext_sha = ext_info.get("sha256")
    if not isinstance(ext_sha, str) or not SHA256_HEX_RE.match(ext_sha):
        raise ValueError("chrome_extension.sha256 must be 64 lowercase hex chars")

    return manifest


def verify_signature_envelope_and_bytes(
    manifest_bytes: bytes,
    sig_bytes: bytes,
    active_keys: dict[str, bytes],
) -> dict[str, Any]:
    if len(sig_bytes) == 0 or len(sig_bytes) > MAX_SIG_BYTES:
        raise ValueError(f"signature envelope size ({len(sig_bytes)} bytes) outside 1..={MAX_SIG_BYTES}")
    try:
        envelope = json.loads(sig_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"invalid signature envelope UTF-8/JSON: {exc}") from exc

    if not isinstance(envelope, dict):
        raise ValueError("signature envelope must be a JSON object")
    if envelope.get("schema_version") != SIGNATURE_SCHEMA_VERSION:
        raise ValueError(f"signature schema_version must be {SIGNATURE_SCHEMA_VERSION}")
    if envelope.get("algorithm") != SIGNATURE_ALGORITHM_ED25519:
        raise ValueError(f"signature algorithm must be '{SIGNATURE_ALGORITHM_ED25519}'")

    key_id = envelope.get("key_id")
    if not isinstance(key_id, str) or key_id not in active_keys:
        raise ValueError(f"signature key_id '{key_id}' is unknown or not active")

    sig_b64 = envelope.get("signature_b64")
    if not isinstance(sig_b64, str):
        raise ValueError("signature_b64 must be a string")
    raw_sig = decode_base64_strict(sig_b64)
    if len(raw_sig) != 64:
        raise ValueError(f"Ed25519 signature must be 64 bytes, got {len(raw_sig)}")

    if not ed25519_verify_strict(active_keys[key_id], manifest_bytes, raw_sig):
        raise ValueError(f"Ed25519 signature verification failed for key_id '{key_id}'")

    return envelope


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Subcommand Implementations
# ---------------------------------------------------------------------------


def run_preflight(
    *,
    repo_root: Path,
    public_keys_path: Path,
    expect_tag: str | None = None,
    expect_version: str | None = None,
    require_active_key: bool = False,
    private_key_env: str | None = None,
    key_id: str | None = None,
) -> dict[str, Any]:
    version = read_synced_versions(repo_root)
    tag = f"v{version}"

    if expect_version is not None and expect_version != version:
        raise ValueError(f"expected version '{expect_version}' != repo version '{version}'")
    if expect_tag is not None and expect_tag != tag:
        raise ValueError(f"expected tag '{expect_tag}' != repo tag '{tag}'")

    active_keys = parse_public_key_ring(public_keys_path, require_active_key=require_active_key)

    if private_key_env:
        raw_env = os.environ.get(private_key_env, "")
        if raw_env.strip():
            seed = parse_ed25519_private_seed(raw_env)
            pub = ed25519_pubkey_from_seed(seed)
            resolve_signing_key_id(active_keys, pub, key_id or os.environ.get(DEFAULT_KEY_ID_ENV) or None)
        elif require_active_key:
            raise ValueError(f"required secret '{private_key_env}' is empty or unset")

    if (repo_root / ".git").exists():
        res = subprocess.run(
            [
                "git",
                "-C",
                str(repo_root),
                "ls-files",
                "extensions/ledr-chrome-mv3/_metadata",
                "scripts/__pycache__",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            raise ValueError(f"forbidden untracked artifacts are tracked in git: {res.stdout.strip()}")

    return {
        "version": version,
        "tag": tag,
        "extension_id": EXPECTED_CHROME_EXTENSION_ID,
        "active_key_ids": sorted(active_keys.keys()),
    }


def run_keygen(
    *,
    key_id: str | None = None,
    fmt: str = "b64",
    write_public_keys: Path | None = None,
    write_private_key_file: Path | None = None,
) -> dict[str, Any]:
    seed = secrets.token_bytes(32)
    pub = ed25519_pubkey_from_seed(seed)
    pub_b64 = base64.b64encode(pub).decode("ascii")
    resolved_key_id = (key_id or "").strip()
    if not resolved_key_id:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        resolved_key_id = f"key-{stamp}-{secrets.token_hex(4)}"

    private_text = (
        encode_pkcs8_pem_from_seed(seed)
        if fmt == "pkcs8-pem"
        else base64.b64encode(seed).decode("ascii")
    )

    key_ring_doc = {
        "schema_version": KEY_RING_SCHEMA_VERSION,
        "keys": [
            {
                "key_id": resolved_key_id,
                "public_key_b64": pub_b64,
                "status": "active",
            }
        ],
    }

    if write_public_keys is not None:
        write_public_keys.parent.mkdir(parents=True, exist_ok=True)
        write_public_keys.write_text(
            json.dumps(key_ring_doc, indent=2) + "\n", encoding="utf-8"
        )

    if write_private_key_file is not None:
        write_private_key_file.parent.mkdir(parents=True, exist_ok=True)
        write_private_key_file.write_text(private_text, encoding="utf-8")
        try:
            os.chmod(write_private_key_file, 0o600)
        except OSError:
            pass
        # Never echo private key to stdout when written to file.
        return {
            "key_id": resolved_key_id,
            "public_key_b64": pub_b64,
            "public_keys_json": key_ring_doc,
        }

    return {
        "key_id": resolved_key_id,
        "public_key_b64": pub_b64,
        "private_key": private_text,
        "public_keys_json": key_ring_doc,
    }


def sign_manifest_file(
    *,
    manifest_path: Path,
    out_sig_path: Path,
    public_keys_path: Path,
    key_id: str | None = None,
    private_key_file: Path | None = None,
    private_key_env: str = DEFAULT_PRIVATE_KEY_ENV,
) -> dict[str, Any]:
    if not manifest_path.is_file():
        raise ValueError(f"manifest file not found: {manifest_path}")
    manifest_bytes = manifest_path.read_bytes()
    validate_manifest_structure(manifest_bytes)

    active_keys = parse_public_key_ring(public_keys_path, require_active_key=True)
    seed = load_private_seed_from_args(
        private_key_file=private_key_file,
        private_key_env=private_key_env,
    )
    pub = ed25519_pubkey_from_seed(seed)
    resolved_key_id = resolve_signing_key_id(
        active_keys,
        pub,
        key_id or os.environ.get(DEFAULT_KEY_ID_ENV) or None,
    )

    sig_raw = ed25519_sign(seed, manifest_bytes)
    envelope = {
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "key_id": resolved_key_id,
        "algorithm": SIGNATURE_ALGORITHM_ED25519,
        "signature_b64": base64.b64encode(sig_raw).decode("ascii"),
    }
    sig_bytes = (json.dumps(envelope, indent=2) + "\n").encode("utf-8")
    verify_signature_envelope_and_bytes(manifest_bytes, sig_bytes, active_keys)

    out_sig_path.parent.mkdir(parents=True, exist_ok=True)
    out_sig_path.write_bytes(sig_bytes)
    return envelope


def _check_archive_path_safe(member_name: str) -> str:
    if not member_name or member_name.startswith(("/", "\\")) or "\\" in member_name:
        raise ValueError(f"unsafe archive entry path '{member_name}'")
    parts = member_name.split("/")
    if any(p in {"", ".", ".."} for p in parts):
        raise ValueError(f"invalid archive path segments in '{member_name}'")
    if any(p in FORBIDDEN_ARCHIVE_SEGMENTS for p in parts):
        raise ValueError(f"forbidden directory in archive path '{member_name}'")
    return member_name


def verify_dist(
    *,
    dist_dir: Path,
    public_keys_path: Path,
    expect_tag: str | None = None,
    expect_version: str | None = None,
) -> dict[str, Any]:
    if not dist_dir.is_dir():
        raise ValueError(f"dist directory not found: {dist_dir}")

    active_keys = parse_public_key_ring(public_keys_path, require_active_key=True)
    manifest_path = dist_dir / "update-manifest.json"
    sig_path = dist_dir / "update-manifest.json.sig"
    sums_path = dist_dir / "SHA256SUMS.txt"

    for p in (manifest_path, sig_path, sums_path):
        if not p.is_file():
            raise ValueError(f"missing required distribution file: {p.name}")

    manifest_bytes = manifest_path.read_bytes()
    sig_bytes = sig_path.read_bytes()

    # Verify Ed25519 signature BEFORE trusting manifest fields.
    envelope = verify_signature_envelope_and_bytes(manifest_bytes, sig_bytes, active_keys)
    manifest = validate_manifest_structure(manifest_bytes, expect_version=expect_version)
    version = manifest["version"]
    tag = manifest["tag"]
    if expect_tag is not None and tag != expect_tag:
        raise ValueError(f"manifest tag '{tag}' != expected '{expect_tag}'")

    setup_name = f"LocalEDR-Setup-v{version}-win-x64.exe"
    portable_name = f"LocalEDR-v{version}-win-x64.zip"
    ext_zip_name = f"LocalEDR-chrome-ext-v{version}.zip"
    expected_files = {
        setup_name,
        portable_name,
        ext_zip_name,
        "SHA256SUMS.txt",
        "update-manifest.json",
        "update-manifest.json.sig",
    }

    actual_entries = {p.name for p in dist_dir.iterdir()}
    if actual_entries != expected_files:
        missing = sorted(expected_files - actual_entries)
        extra = sorted(actual_entries - expected_files)
        raise ValueError(
            f"dist directory artifact mismatch (missing={missing}, extra={extra})"
        )

    setup_path = dist_dir / setup_name
    portable_path = dist_dir / portable_name
    ext_zip_path = dist_dir / ext_zip_name

    setup_size = setup_path.stat().st_size
    if setup_size != manifest["size_bytes"]:
        raise ValueError(
            f"installer size mismatch: actual={setup_size}, manifest={manifest['size_bytes']}"
        )
    setup_sha = sha256_file(setup_path)
    if setup_sha != manifest["sha256"]:
        raise ValueError(
            f"installer sha256 mismatch: actual={setup_sha}, manifest={manifest['sha256']}"
        )

    ext_sha = sha256_file(ext_zip_path)
    if ext_sha != manifest["chrome_extension"]["sha256"]:
        raise ValueError(
            f"extension zip sha256 mismatch: actual={ext_sha}, manifest={manifest['chrome_extension']['sha256']}"
        )
    portable_sha = sha256_file(portable_path)

    # Validate SHA256SUMS.txt covers exact 3 distributables.
    expected_sums = {
        setup_name: setup_sha,
        portable_name: portable_sha,
        ext_zip_name: ext_sha,
    }
    seen_sums: dict[str, str] = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        m = re.match(r"^([0-9a-f]{64})  (.+)$", line)
        if not m:
            raise ValueError(f"invalid SHA256SUMS.txt line: {line!r}")
        digest, fname = m.group(1), m.group(2)
        if fname in seen_sums:
            raise ValueError(f"duplicate entry '{fname}' in SHA256SUMS.txt")
        seen_sums[fname] = digest
    if seen_sums != expected_sums:
        raise ValueError(
            f"SHA256SUMS.txt mismatch: expected keys={sorted(expected_sums)}, actual={sorted(seen_sums)}"
        )

    # Inspect portable zip contents.
    with zipfile.ZipFile(portable_path, "r") as zf:
        portable_members = set()
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = _check_archive_path_safe(info.filename)
            if name.lower().endswith(".pdb"):
                raise ValueError(f"forbidden .pdb symbol file in portable zip: '{name}'")
            portable_members.add(name)
        missing_portable = sorted(REQUIRED_PORTABLE_ZIP_FILES - portable_members)
        if missing_portable:
            raise ValueError(f"portable zip missing required files: {missing_portable}")

    # Inspect Chrome extension zip contents.
    with zipfile.ZipFile(ext_zip_path, "r") as zf:
        ext_members = set()
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = _check_archive_path_safe(info.filename)
            if name == "package.json" or name.lower().endswith((".pem", ".key")):
                raise ValueError(f"forbidden file in Chrome extension zip: '{name}'")
            ext_members.add(name)
        missing_ext = sorted(REQUIRED_EXTENSION_ZIP_FILES - ext_members)
        if missing_ext:
            raise ValueError(f"Chrome extension zip missing required files: {missing_ext}")
        ext_manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        if ext_manifest.get("version") != version:
            raise ValueError(f"extension zip manifest.json version != '{version}'")
        if derive_chrome_extension_id(str(ext_manifest.get("key") or "")) != EXPECTED_CHROME_EXTENSION_ID:
            raise ValueError("extension zip manifest.json key does not derive pinned extension ID")

    return {
        "version": version,
        "tag": tag,
        "key_id": envelope["key_id"],
        "installer_sha256": setup_sha,
        "extension_sha256": ext_sha,
    }


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LocalEDR release verification and signing CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_pre = sub.add_parser("preflight", help="Verify repo version sync, extension ID, and public keys")
    p_pre.add_argument("--repo-root", type=Path, default=_default_repo_root())
    p_pre.add_argument("--public-keys", type=Path, default=None)
    p_pre.add_argument("--expect-tag", default=None)
    p_pre.add_argument("--expect-version", default=None)
    p_pre.add_argument("--require-active-key", action="store_true")
    p_pre.add_argument("--private-key-env", default=None)
    p_pre.add_argument("--key-id", default=None)
    p_pre.add_argument("--json", action="store_true")

    p_kg = sub.add_parser("keygen", help="Generate a new Ed25519 release signing keypair")
    p_kg.add_argument("--key-id", default=None)
    p_kg.add_argument("--format", choices=("b64", "pkcs8-pem"), default="b64")
    p_kg.add_argument("--write-public-keys", type=Path, default=None)
    p_kg.add_argument("--write-private-key-file", type=Path, default=None)

    p_sign = sub.add_parser("sign-manifest", help="Sign update-manifest.json with Ed25519")
    p_sign.add_argument("--manifest", type=Path, required=True)
    p_sign.add_argument("--out", type=Path, default=None)
    p_sign.add_argument(
        "--public-keys",
        type=Path,
        default=_default_repo_root() / "packaging" / "update-public-keys.json",
    )
    p_sign.add_argument("--key-id", default=None)
    p_sign.add_argument("--private-key-file", type=Path, default=None)
    p_sign.add_argument("--private-key-env", default=DEFAULT_PRIVATE_KEY_ENV)

    p_ver = sub.add_parser("verify-dist", help="Verify all 6 release artifacts in dist-dir")
    p_ver.add_argument("--dist-dir", type=Path, required=True)
    p_ver.add_argument(
        "--public-keys",
        type=Path,
        default=_default_repo_root() / "packaging" / "update-public-keys.json",
    )
    p_ver.add_argument("--expect-tag", default=None)
    p_ver.add_argument("--expect-version", default=None)
    p_ver.add_argument("--json", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "preflight":
            pub_keys = args.public_keys or (args.repo_root / "packaging" / "update-public-keys.json")
            res = run_preflight(
                repo_root=args.repo_root,
                public_keys_path=pub_keys,
                expect_tag=args.expect_tag,
                expect_version=args.expect_version,
                require_active_key=args.require_active_key,
                private_key_env=args.private_key_env,
                key_id=args.key_id,
            )
            if args.json:
                print(json.dumps(res, indent=2))
            else:
                print(
                    f"Preflight OK: version={res['version']} tag={res['tag']} "
                    f"ext={res['extension_id']} active_keys={res['active_key_ids']}"
                )
            return 0

        if args.command == "keygen":
            res = run_keygen(
                key_id=args.key_id,
                fmt=args.format,
                write_public_keys=args.write_public_keys,
                write_private_key_file=args.write_private_key_file,
            )
            print(json.dumps(res, indent=2))
            return 0

        if args.command == "sign-manifest":
            out_path = args.out or Path(f"{args.manifest}.sig")
            env = sign_manifest_file(
                manifest_path=args.manifest,
                out_sig_path=out_path,
                public_keys_path=args.public_keys,
                key_id=args.key_id,
                private_key_file=args.private_key_file,
                private_key_env=args.private_key_env,
            )
            print(f"Signed {args.manifest} -> {out_path} (key_id={env['key_id']})")
            return 0

        if args.command == "verify-dist":
            res = verify_dist(
                dist_dir=args.dist_dir,
                public_keys_path=args.public_keys,
                expect_tag=args.expect_tag,
                expect_version=args.expect_version,
            )
            if args.json:
                print(json.dumps(res, indent=2))
            else:
                print(
                    f"verify-dist OK: tag={res['tag']} key_id={res['key_id']} "
                    f"installer_sha256={res['installer_sha256']}"
                )
            return 0

        parser.error(f"unknown command {args.command}")
        return 2
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
