//! Two-tier binary allowlist evaluation (`決定記録 L-04`), streaming SHA-256 hashing,
//! and Windows Authenticode signature verification (`WinVerifyTrust` + `CryptQueryObject`).

use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;

use ledr_proto::{AllowlistRuleRecord, AuthenticodeInfo, RuleScope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SHA256_BUF_LEN: usize = 65_536;

/// Resolved identity of an executable binary used for two-tier allowlist checks (`L-04`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BinaryIdentity {
    pub exe_path: String,
    pub sha256: Option<String>,
    pub authenticode: Option<AuthenticodeInfo>,
}

impl BinaryIdentity {
    /// Inspects `path` on disk, collecting streaming SHA-256 and Authenticode metadata gracefully.
    pub fn from_path(path: impl AsRef<Path>) -> Self {
        let p = path.as_ref();
        Self {
            exe_path: p.to_string_lossy().into_owned(),
            sha256: compute_file_sha256_hex(p).ok(),
            authenticode: inspect_authenticode(p),
        }
    }
}

/// Computes the streaming lowercase hex SHA-256 digest of the file at `path`.
pub fn compute_file_sha256_hex(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; SHA256_BUF_LEN];
    loop {
        let read_bytes = file.read(&mut buf)?;
        if read_bytes == 0 {
            break;
        }
        hasher.update(&buf[..read_bytes]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Performs ASCII case-insensitive wildcard (`*`) matching with `/` and `\` normalization.
pub fn matches_path_pattern(exe_path: &str, pattern: &str) -> bool {
    let s: Vec<char> = exe_path.chars().map(normalize_path_char).collect();
    let p: Vec<char> = pattern.chars().map(normalize_path_char).collect();

    let (mut si, mut pi) = (0usize, 0usize);
    let (mut star_pi, mut match_si) = (None, 0usize);

    while si < s.len() {
        if pi < p.len() && p[pi] == s[si] {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            match_si = si;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            match_si += 1;
            si = match_si;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[inline]
fn normalize_path_char(ch: char) -> char {
    if ch == '/' {
        '\\'
    } else {
        ch.to_ascii_lowercase()
    }
}

/// Evaluates whether `identity` (optionally accessing `target`) is permitted by `rules`
/// under `scope` using the `L-04` two-tier model:
/// - **Signed tier**: when `rule.signer_subject` is present and non-empty, requires
///   `identity.authenticode` present, matching `signer_subject` (case-insensitive exact or CN),
///   a non-empty non-all-zero `rule.root_thumbprint` matching `authenticode.root_thumbprint`
///   case-insensitively, optional `rule.sha256` match if set, `exe_path_pattern` match, and
///   optional `allowed_target` match. Signed rules with missing, empty, or all-zero
///   `root_thumbprint` never match.
/// - **Unsigned tier**: when `rule.signer_subject` is absent/empty, requires `exe_path_pattern`
///   match, non-empty `rule.sha256` matching `identity.sha256`, and optional `allowed_target` match.
///   Never allows an unsigned rule with `sha256: None` or empty.
pub fn is_allowed_by_rules(
    identity: &BinaryIdentity,
    target: Option<&str>,
    scope: RuleScope,
    rules: &[AllowlistRuleRecord],
) -> bool {
    rules
        .iter()
        .any(|rule| rule.scope == scope && rule_matches_identity(rule, identity, target))
}

fn rule_matches_identity(
    rule: &AllowlistRuleRecord,
    identity: &BinaryIdentity,
    target: Option<&str>,
) -> bool {
    if rule.exe_path_pattern.trim().is_empty()
        || !matches_path_pattern(&identity.exe_path, &rule.exe_path_pattern)
    {
        return false;
    }

    if let Some(allowed_target) = rule.allowed_target.as_deref() {
        let Some(actual_target) = target else {
            return false;
        };
        if !matches_path_pattern(actual_target, allowed_target) {
            return false;
        }
    }

    let expected_signer = rule
        .signer_subject
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    match expected_signer {
        Some(rule_signer) => {
            let Some(auth) = identity.authenticode.as_ref() else {
                return false;
            };
            if !signer_subject_matches(&auth.signer_subject, rule_signer) {
                return false;
            }
            let Some(rule_tp) = rule
                .root_thumbprint
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.chars().all(|c| c == '0'))
            else {
                return false;
            };
            let actual_tp = auth.root_thumbprint.trim();
            if actual_tp.is_empty()
                || actual_tp.chars().all(|c| c == '0')
                || !actual_tp.eq_ignore_ascii_case(rule_tp)
            {
                return false;
            }
            if let Some(rule_sha) = rule
                .sha256
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let matches_sha = identity
                    .sha256
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|s| s.eq_ignore_ascii_case(rule_sha));
                if !matches_sha {
                    return false;
                }
            }
            true
        }
        None => {
            let Some(rule_sha) = rule
                .sha256
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                // L-04: Unsigned rule MUST specify a non-empty SHA-256 digest.
                return false;
            };
            identity
                .sha256
                .as_deref()
                .map(str::trim)
                .is_some_and(|s| !s.is_empty() && s.eq_ignore_ascii_case(rule_sha))
        }
    }
}

/// Checks case-insensitive exact DN match or CN match between an actual Authenticode
/// `signer_subject` and an expected `signer_subject` pattern.
pub fn signer_subject_matches(actual: &str, expected: &str) -> bool {
    let actual_t = actual.trim();
    let expected_t = expected.trim();
    if actual_t.is_empty() || expected_t.is_empty() {
        return false;
    }
    if actual_t.eq_ignore_ascii_case(expected_t) {
        return true;
    }

    let actual_parts = split_rdns(actual_t);
    let expected_parts = split_rdns(expected_t);

    if actual_parts.len() == expected_parts.len()
        && actual_parts.len() > 1
        && actual_parts
            .iter()
            .zip(expected_parts.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    {
        return true;
    }

    // Allow CN match when at least one side specifies only a CN / simple display name.
    if actual_parts.len() <= 1 || expected_parts.len() <= 1 {
        if let (Some(a_cn), Some(e_cn)) = (extract_cn(&actual_parts), extract_cn(&expected_parts)) {
            return a_cn.eq_ignore_ascii_case(e_cn);
        }
    }

    false
}

fn split_rdns(dn: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for ch in dn.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            cur.push(ch);
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            cur.push(ch);
            continue;
        }
        if ch == ',' && !in_quotes {
            let trimmed = cur.trim().to_string();
            if !trimmed.is_empty() {
                parts.push(trimmed);
            }
            cur.clear();
            continue;
        }
        cur.push(ch);
    }

    let trimmed = cur.trim().to_string();
    if !trimmed.is_empty() {
        parts.push(trimmed);
    }
    parts
}

fn extract_cn(rdns: &[String]) -> Option<&str> {
    for part in rdns {
        if let Some((key, val)) = part.split_once('=') {
            if key.trim().eq_ignore_ascii_case("CN") {
                let unquoted = val.trim().trim_matches('"').trim();
                if !unquoted.is_empty() {
                    return Some(unquoted);
                }
            }
        }
    }
    if rdns.len() == 1 && !rdns[0].contains('=') {
        let s = rdns[0].trim();
        if !s.is_empty() {
            return Some(s);
        }
    }
    None
}

/// Verifies the Windows Authenticode signature of `path` (supporting both embedded PE
/// signatures and OS catalog signatures) and extracts `(signer_subject, root_thumbprint)`.
///
/// Returns `None` gracefully on missing, unreadable, unsigned, or untrusted files.
pub fn inspect_authenticode(path: &Path) -> Option<AuthenticodeInfo> {
    if path.as_os_str().is_empty() {
        return None;
    }
    let file = File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    let path_w = encode_wide_nul(path.as_os_str());

    if verify_embedded_wintrust(&path_w) {
        if let Some(info) =
            extract_authenticode_from_signed_file(&path_w, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED)
        {
            return Some(info);
        }
    }

    verify_catalog_authenticode(&file, &path_w)
}

fn encode_wide_nul(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn verify_embedded_wintrust(path_w: &[u16]) -> bool {
    let mut file_info = WINTRUST_FILE_INFO {
        cb_struct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwsz_file_path: path_w.as_ptr(),
        h_file: ptr::null_mut(),
        pg_known_subject: ptr::null_mut(),
    };

    let mut data = WINTRUST_DATA {
        cb_struct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        p_policy_callback_data: ptr::null_mut(),
        p_sip_client_data: ptr::null_mut(),
        dw_ui_choice: WTD_UI_NONE,
        fdw_revocation_checks: WTD_REVOKE_NONE,
        dw_union_choice: WTD_CHOICE_FILE,
        choice: WINTRUST_DATA_CHOICE {
            p_file: &mut file_info,
        },
        dw_state_action: WTD_STATEACTION_VERIFY,
        h_wvt_state_data: ptr::null_mut(),
        pwsz_url_reference: ptr::null_mut(),
        dw_prov_flags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
        dw_ui_context: 0,
        p_signature_settings: ptr::null_mut(),
    };

    run_win_verify_trust(&mut data) == 0
}

fn verify_catalog_authenticode(file: &File, path_w: &[u16]) -> Option<AuthenticodeInfo> {
    let sha256_w: Vec<u16> = "SHA256\0".encode_utf16().collect();
    let mut h_cat_admin: isize = 0;

    // SAFETY: `h_cat_admin` receives an owned catalog admin context handle if call succeeds.
    let ok = unsafe {
        CryptCATAdminAcquireContext2(
            &mut h_cat_admin,
            ptr::null(),
            sha256_w.as_ptr(),
            ptr::null(),
            0,
        )
    };
    if ok != 0 && h_cat_admin != 0 {
        let _guard = CatAdminGuard(h_cat_admin);
        if let Some(info) = verify_with_cat_admin(h_cat_admin, file, path_w, true) {
            return Some(info);
        }
    }

    let mut h_legacy_admin: isize = 0;
    // SAFETY: Legacy SHA-1 catalog admin context fallback.
    let ok_legacy = unsafe { CryptCATAdminAcquireContext(&mut h_legacy_admin, ptr::null(), 0) };
    if ok_legacy != 0 && h_legacy_admin != 0 {
        let _guard = CatAdminGuard(h_legacy_admin);
        if let Some(info) = verify_with_cat_admin(h_legacy_admin, file, path_w, false) {
            return Some(info);
        }
    }

    None
}

fn verify_with_cat_admin(
    h_cat_admin: isize,
    file: &File,
    path_w: &[u16],
    use_v2_hash: bool,
) -> Option<AuthenticodeInfo> {
    let raw_handle = file.as_raw_handle();
    let mut hash_len: u32 = 0;

    // SAFETY: Query required hash buffer length for open file handle.
    let size_ok = unsafe {
        if use_v2_hash {
            CryptCATAdminCalcHashFromFileHandle2(
                h_cat_admin,
                raw_handle,
                &mut hash_len,
                ptr::null_mut(),
                0,
            )
        } else {
            CryptCATAdminCalcHashFromFileHandle(raw_handle, &mut hash_len, ptr::null_mut(), 0)
        }
    };
    if size_ok == 0 || hash_len == 0 {
        return None;
    }

    let mut hash = vec![0u8; hash_len as usize];
    // SAFETY: `hash` is sized to `hash_len` bytes as returned by the size query.
    let hash_ok = unsafe {
        if use_v2_hash {
            CryptCATAdminCalcHashFromFileHandle2(
                h_cat_admin,
                raw_handle,
                &mut hash_len,
                hash.as_mut_ptr(),
                0,
            )
        } else {
            CryptCATAdminCalcHashFromFileHandle(raw_handle, &mut hash_len, hash.as_mut_ptr(), 0)
        }
    };
    if hash_ok == 0 || hash_len == 0 {
        return None;
    }
    hash.truncate(hash_len as usize);

    let member_tag: String = hash.iter().map(|b| format!("{b:02X}")).collect();
    let member_tag_w: Vec<u16> = member_tag
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut h_cat_info: isize = 0;
    loop {
        // SAFETY: Enumerates system catalogs matching `hash`, releasing previous handle via `h_cat_info`.
        h_cat_info = unsafe {
            CryptCATAdminEnumCatalogFromHash(
                h_cat_admin,
                hash.as_ptr(),
                hash.len() as u32,
                0,
                &mut h_cat_info,
            )
        };
        if h_cat_info == 0 {
            break;
        }

        let mut cat_info = CATALOG_INFO {
            cb_struct: std::mem::size_of::<CATALOG_INFO>() as u32,
            wsz_catalog_file: [0u16; 260],
        };
        // SAFETY: `h_cat_info` is a live catalog info context from `CryptCATAdminEnumCatalogFromHash`.
        if unsafe { CryptCATCatalogInfoFromContext(h_cat_info, &mut cat_info, 0) } != 0 {
            let mut wt_cat = WINTRUST_CATALOG_INFO {
                cb_struct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                dw_catalog_version: 0,
                pcwsz_catalog_file_path: cat_info.wsz_catalog_file.as_ptr(),
                pcwsz_member_tag: member_tag_w.as_ptr(),
                pcwsz_member_file_path: path_w.as_ptr(),
                h_member_file: raw_handle,
                pb_calculated_file_hash: hash.as_mut_ptr(),
                cb_calculated_file_hash: hash.len() as u32,
                pc_catalog_context: ptr::null_mut(),
                h_cat_admin,
            };

            let mut data = WINTRUST_DATA {
                cb_struct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                p_policy_callback_data: ptr::null_mut(),
                p_sip_client_data: ptr::null_mut(),
                dw_ui_choice: WTD_UI_NONE,
                fdw_revocation_checks: WTD_REVOKE_NONE,
                dw_union_choice: WTD_CHOICE_CATALOG,
                choice: WINTRUST_DATA_CHOICE {
                    p_catalog: &mut wt_cat,
                },
                dw_state_action: WTD_STATEACTION_VERIFY,
                h_wvt_state_data: ptr::null_mut(),
                pwsz_url_reference: ptr::null_mut(),
                dw_prov_flags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
                dw_ui_context: 0,
                p_signature_settings: ptr::null_mut(),
            };

            if run_win_verify_trust(&mut data) == 0 {
                if let Some(info) = extract_authenticode_from_signed_file(
                    &cat_info.wsz_catalog_file,
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                ) {
                    // SAFETY: Release current catalog context before returning.
                    unsafe {
                        CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0);
                    }
                    return Some(info);
                }
            }
        }
    }

    None
}

fn run_win_verify_trust(data: &mut WINTRUST_DATA) -> i32 {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `action` and `data` are valid `WINTRUST` structs; state is closed unconditionally below.
    let status = unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            data as *mut WINTRUST_DATA as *mut c_void,
        )
    };
    data.dw_state_action = WTD_STATEACTION_CLOSE;
    // SAFETY: Releases `h_wvt_state_data` allocated by the `WTD_STATEACTION_VERIFY` call.
    unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            data as *mut WINTRUST_DATA as *mut c_void,
        );
    }
    status
}

fn extract_authenticode_from_signed_file(
    path_w: &[u16],
    expected_content_flags: u32,
) -> Option<AuthenticodeInfo> {
    let mut h_store: *mut c_void = ptr::null_mut();
    let mut h_msg: *mut c_void = ptr::null_mut();

    // SAFETY: `path_w` is NUL-terminated UTF-16; `h_store` and `h_msg` are wrapped in RAII guards below.
    let query_ok = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path_w.as_ptr() as *const c_void,
            expected_content_flags,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut h_store,
            &mut h_msg,
            ptr::null_mut(),
        )
    };
    if query_ok == 0 || h_store.is_null() || h_msg.is_null() {
        if !h_msg.is_null() {
            unsafe { CryptMsgClose(h_msg) };
        }
        if !h_store.is_null() {
            unsafe { CertCloseStore(h_store, 0) };
        }
        return None;
    }

    let _store_guard = CertStoreGuard(h_store);
    let _msg_guard = CryptMsgGuard(h_msg);

    let mut signer_info_size: u32 = 0;
    // SAFETY: Query required buffer size for `CMSG_SIGNER_INFO`.
    let size_ok = unsafe {
        CryptMsgGetParam(
            h_msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            ptr::null_mut(),
            &mut signer_info_size,
        )
    };
    if size_ok == 0 || (signer_info_size as usize) < std::mem::size_of::<CMSG_SIGNER_INFO>() {
        return None;
    }

    let mut signer_buf = vec![0u8; signer_info_size as usize];
    // SAFETY: `signer_buf` has `signer_info_size` writable bytes.
    let param_ok = unsafe {
        CryptMsgGetParam(
            h_msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            signer_buf.as_mut_ptr() as *mut c_void,
            &mut signer_info_size,
        )
    };
    if param_ok == 0 {
        return None;
    }

    // SAFETY: Buffer was populated by `CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM)` and verified >= struct size.
    let signer_info = unsafe { ptr::read_unaligned(signer_buf.as_ptr() as *const CMSG_SIGNER_INFO) };

    let mut search_cert_info: CERT_INFO = unsafe { std::mem::zeroed() };
    search_cert_info.issuer = signer_info.issuer;
    search_cert_info.serial_number = signer_info.serial_number;

    // SAFETY: Searches `h_store` for the signer certificate matching Issuer + SerialNumber.
    let signer_cert = unsafe {
        CertFindCertificateInStore(
            h_store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            &search_cert_info as *const CERT_INFO as *const c_void,
            ptr::null(),
        )
    };
    if signer_cert.is_null() {
        return None;
    }
    let _signer_guard = CertContextGuard(signer_cert);

    let signer_subject = read_cert_subject_name(signer_cert)?;
    let root_thumbprint = read_chain_root_thumbprint(signer_cert, h_store)?;

    Some(AuthenticodeInfo {
        signer_subject,
        root_thumbprint,
    })
}

fn read_cert_subject_name(cert: *const CERT_CONTEXT) -> Option<String> {
    let mut str_type: u32 = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
    let mut buf = [0u16; 1024];

    // SAFETY: `cert` is a valid `CERT_CONTEXT`; `str_type` is a valid `DWORD` parameter for `CERT_NAME_RDN_TYPE`.
    let count = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_RDN_TYPE,
            0,
            &mut str_type as *mut u32 as *const c_void,
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    };
    if count > 1 {
        let len = usize::try_from(count - 1).ok()?.min(buf.len());
        let name = String::from_utf16_lossy(&buf[..len]).trim().to_string();
        if !name.is_empty() {
            return Some(name);
        }
    }

    // Fallback to simple display name if RDN string formatting was unavailable.
    // SAFETY: `cert` is a valid `CERT_CONTEXT`.
    let simple_count = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            ptr::null(),
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    };
    if simple_count > 1 {
        let len = usize::try_from(simple_count - 1).ok()?.min(buf.len());
        let name = String::from_utf16_lossy(&buf[..len]).trim().to_string();
        if !name.is_empty() {
            return Some(name);
        }
    }

    None
}

const CERT_TRUST_IS_NOT_SIGNATURE_VALID: u32 = 0x0000_0008;
const CERT_TRUST_IS_UNTRUSTED_ROOT: u32 = 0x0000_0020;
const CERT_TRUST_IS_PARTIAL_CHAIN: u32 = 0x0001_0000;
const CHAIN_FALLBACK_ERROR_MASK: u32 =
    CERT_TRUST_IS_NOT_SIGNATURE_VALID | CERT_TRUST_IS_UNTRUSTED_ROOT | CERT_TRUST_IS_PARTIAL_CHAIN;

fn build_chain_root_thumbprint(
    signer_cert: *const CERT_CONTEXT,
    additional_store: *mut c_void,
    require_clean_trust: bool,
) -> Option<String> {
    let mut chain_para: CERT_CHAIN_PARA = unsafe { std::mem::zeroed() };
    chain_para.cb_size = std::mem::size_of::<CERT_CHAIN_PARA>() as u32;
    let mut chain_ctx: *const CERT_CHAIN_CONTEXT = ptr::null();

    // SAFETY: Builds the local certificate chain for `signer_cert` without network revocation fetches.
    let ok = unsafe {
        CertGetCertificateChain(
            ptr::null_mut(),
            signer_cert,
            ptr::null(),
            additional_store,
            &chain_para,
            CERT_CHAIN_CACHE_END_CERT,
            ptr::null(),
            &mut chain_ctx,
        )
    };
    if ok == 0 || chain_ctx.is_null() {
        return None;
    }
    let _chain_guard = CertChainGuard(chain_ctx);

    // SAFETY: `chain_ctx` was populated by `CertGetCertificateChain`.
    let chain = unsafe { &*chain_ctx };
    if chain.c_chain == 0 || chain.rgp_chain.is_null() {
        return None;
    }
    if require_clean_trust && (chain.trust_status.dw_error_status & CHAIN_FALLBACK_ERROR_MASK) != 0 {
        return None;
    }
    // SAFETY: `rgp_chain` has at least `c_chain >= 1` entries.
    let simple_chain_ptr = unsafe { *chain.rgp_chain };
    if simple_chain_ptr.is_null() {
        return None;
    }
    // SAFETY: `simple_chain_ptr` is a valid `CERT_SIMPLE_CHAIN` pointer inside `chain_ctx`.
    let simple_chain = unsafe { &*simple_chain_ptr };
    if simple_chain.c_element == 0 || simple_chain.rgp_element.is_null() {
        return None;
    }

    let last_idx = (simple_chain.c_element - 1) as usize;
    // SAFETY: `rgp_element` has `c_element` pointers; `last_idx` is `< c_element`.
    let root_elem_ptr = unsafe { *simple_chain.rgp_element.add(last_idx) };
    if root_elem_ptr.is_null() {
        return None;
    }
    // SAFETY: `root_elem_ptr` is a valid `CERT_CHAIN_ELEMENT` inside `chain_ctx`.
    let root_cert = unsafe { (*root_elem_ptr).p_cert_context };
    if root_cert.is_null() {
        return None;
    }

    let mut hash = [0u8; 20];
    let mut hash_len = u32::try_from(hash.len()).unwrap_or(20);
    // SAFETY: Queries the 20-byte SHA-1 thumbprint property of `root_cert`.
    let prop_ok = unsafe {
        CertGetCertificateContextProperty(
            root_cert,
            CERT_SHA1_HASH_PROP_ID,
            hash.as_mut_ptr() as *mut c_void,
            &mut hash_len,
        )
    };
    if prop_ok == 0 || hash_len == 0 {
        return None;
    }

    let used = (hash_len as usize).min(hash.len());
    Some(hash[..used].iter().map(|b| format!("{b:02X}")).collect())
}

fn read_chain_root_thumbprint(
    signer_cert: *const CERT_CONTEXT,
    additional_store: *mut c_void,
) -> Option<String> {
    // Prefer the direct system-store chain first so embedded cross-signed CA certs (e.g. DigiCert
    // Trusted Root G4 cross-signed by Assured ID Root CA) do not shadow the direct Root anchor;
    // fall back to `additional_store` when an intermediate CA is not cached locally.
    if let Some(tp) = build_chain_root_thumbprint(signer_cert, ptr::null_mut(), true) {
        return Some(tp);
    }
    if !additional_store.is_null() {
        return build_chain_root_thumbprint(signer_cert, additional_store, false);
    }
    build_chain_root_thumbprint(signer_cert, ptr::null_mut(), false)
}

struct CatAdminGuard(isize);
impl Drop for CatAdminGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { CryptCATAdminReleaseContext(self.0, 0) };
        }
    }
}

struct CertStoreGuard(*mut c_void);
impl Drop for CertStoreGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CertCloseStore(self.0, 0) };
        }
    }
}

struct CryptMsgGuard(*mut c_void);
impl Drop for CryptMsgGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CryptMsgClose(self.0) };
        }
    }
}

struct CertContextGuard(*const CERT_CONTEXT);
impl Drop for CertContextGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CertFreeCertificateContext(self.0) };
        }
    }
}

struct CertChainGuard(*const CERT_CHAIN_CONTEXT);
impl Drop for CertChainGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CertFreeCertificateChain(self.0) };
        }
    }
}

// --- Win32 FFI bindings (`wintrust.dll` & `crypt32.dll`) ---

const WTD_UI_NONE: u32 = 2;
const WTD_REVOKE_NONE: u32 = 0;
const WTD_CHOICE_FILE: u32 = 1;
const WTD_CHOICE_CATALOG: u32 = 2;
const WTD_STATEACTION_VERIFY: u32 = 1;
const WTD_STATEACTION_CLOSE: u32 = 2;
const WTD_REVOCATION_CHECK_NONE: u32 = 0x0010;
const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x1000;

const CERT_QUERY_OBJECT_FILE: u32 = 1;
const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED: u32 = 256;
const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED: u32 = 1024;
const CERT_QUERY_FORMAT_FLAG_ALL: u32 = 14;
const CMSG_SIGNER_INFO_PARAM: u32 = 6;
const X509_ASN_ENCODING: u32 = 1;
const PKCS_7_ASN_ENCODING: u32 = 0x0001_0000;
const CERT_FIND_SUBJECT_CERT: u32 = 720_896;
const CERT_NAME_RDN_TYPE: u32 = 2;
const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
const CERT_X500_NAME_STR: u32 = 3;
const CERT_NAME_STR_REVERSE_FLAG: u32 = 0x0200_0000;
const CERT_SHA1_HASH_PROP_ID: u32 = 3;
const CERT_CHAIN_CACHE_END_CERT: u32 = 1;

#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
#[derive(Clone, Copy)]
struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID = GUID {
    data1: 0x00AA_C56B,
    data2: 0xCD44,
    data3: 0x11D0,
    data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};

#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
#[derive(Clone, Copy)]
struct FILETIME {
    dw_low_date_time: u32,
    dw_high_date_time: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CRYPTOAPI_BLOB {
    cb_data: u32,
    pb_data: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CRYPT_BIT_BLOB {
    cb_data: u32,
    pb_data: *mut u8,
    c_unused_bits: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CRYPT_ALGORITHM_IDENTIFIER {
    psz_obj_id: *mut u8,
    parameters: CRYPTOAPI_BLOB,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CRYPT_ATTRIBUTES {
    c_attr: u32,
    rg_attr: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CMSG_SIGNER_INFO {
    dw_version: u32,
    issuer: CRYPTOAPI_BLOB,
    serial_number: CRYPTOAPI_BLOB,
    hash_algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    hash_encryption_algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    encrypted_hash: CRYPTOAPI_BLOB,
    auth_attrs: CRYPT_ATTRIBUTES,
    unauth_attrs: CRYPT_ATTRIBUTES,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CERT_PUBLIC_KEY_INFO {
    algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    public_key: CRYPT_BIT_BLOB,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CERT_INFO {
    dw_version: u32,
    serial_number: CRYPTOAPI_BLOB,
    signature_algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    issuer: CRYPTOAPI_BLOB,
    not_before: FILETIME,
    not_after: FILETIME,
    subject: CRYPTOAPI_BLOB,
    subject_public_key_info: CERT_PUBLIC_KEY_INFO,
    issuer_unique_id: CRYPT_BIT_BLOB,
    subject_unique_id: CRYPT_BIT_BLOB,
    c_extension: u32,
    rg_extension: *mut c_void,
}

#[repr(C)]
struct CERT_CONTEXT {
    dw_cert_encoding_type: u32,
    pb_cert_encoded: *mut u8,
    cb_cert_encoded: u32,
    p_cert_info: *mut CERT_INFO,
    h_cert_store: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CERT_TRUST_STATUS {
    dw_error_status: u32,
    dw_info_status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CERT_USAGE_MATCH {
    dw_type: u32,
    c_usage_identifier: u32,
    rgpsz_usage_identifier: *mut *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CERT_CHAIN_PARA {
    cb_size: u32,
    requested_usage: CERT_USAGE_MATCH,
    requested_issuance_policy: CERT_USAGE_MATCH,
    dw_url_retrieval_timeout: u32,
    f_check_revocation_freshness_time: i32,
    dw_revocation_freshness_time: u32,
    pft_cache_resync: *mut FILETIME,
    p_strong_sign_para: *mut c_void,
    dw_strong_sign_flags: u32,
}

#[repr(C)]
struct CERT_CHAIN_ELEMENT {
    cb_size: u32,
    p_cert_context: *const CERT_CONTEXT,
    trust_status: CERT_TRUST_STATUS,
}

#[repr(C)]
struct CERT_SIMPLE_CHAIN {
    cb_size: u32,
    trust_status: CERT_TRUST_STATUS,
    c_element: u32,
    rgp_element: *mut *mut CERT_CHAIN_ELEMENT,
}

#[repr(C)]
struct CERT_CHAIN_CONTEXT {
    cb_size: u32,
    trust_status: CERT_TRUST_STATUS,
    c_chain: u32,
    rgp_chain: *mut *mut CERT_SIMPLE_CHAIN,
}

#[repr(C)]
struct WINTRUST_FILE_INFO {
    cb_struct: u32,
    pcwsz_file_path: *const u16,
    h_file: *mut c_void,
    pg_known_subject: *mut GUID,
}

#[repr(C)]
struct WINTRUST_CATALOG_INFO {
    cb_struct: u32,
    dw_catalog_version: u32,
    pcwsz_catalog_file_path: *const u16,
    pcwsz_member_tag: *const u16,
    pcwsz_member_file_path: *const u16,
    h_member_file: *mut c_void,
    pb_calculated_file_hash: *mut u8,
    cb_calculated_file_hash: u32,
    pc_catalog_context: *mut c_void,
    h_cat_admin: isize,
}

#[repr(C)]
union WINTRUST_DATA_CHOICE {
    p_file: *mut WINTRUST_FILE_INFO,
    p_catalog: *mut WINTRUST_CATALOG_INFO,
}

#[repr(C)]
struct WINTRUST_DATA {
    cb_struct: u32,
    p_policy_callback_data: *mut c_void,
    p_sip_client_data: *mut c_void,
    dw_ui_choice: u32,
    fdw_revocation_checks: u32,
    dw_union_choice: u32,
    choice: WINTRUST_DATA_CHOICE,
    dw_state_action: u32,
    h_wvt_state_data: *mut c_void,
    pwsz_url_reference: *mut u16,
    dw_prov_flags: u32,
    dw_ui_context: u32,
    p_signature_settings: *mut c_void,
}

#[repr(C)]
struct CATALOG_INFO {
    cb_struct: u32,
    wsz_catalog_file: [u16; 260],
}

#[link(name = "wintrust.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn WinVerifyTrust(hwnd: *mut c_void, pg_action_id: *mut GUID, p_wvt_data: *mut c_void) -> i32;

    fn CryptCATAdminAcquireContext(
        ph_cat_admin: *mut isize,
        pg_subsystem: *const GUID,
        dw_flags: u32,
    ) -> i32;

    fn CryptCATAdminAcquireContext2(
        ph_cat_admin: *mut isize,
        pg_subsystem: *const GUID,
        pwsz_hash_algorithm: *const u16,
        p_strong_hash_policy: *const c_void,
        dw_flags: u32,
    ) -> i32;

    fn CryptCATAdminCalcHashFromFileHandle(
        h_file: *mut c_void,
        pcb_hash: *mut u32,
        pb_hash: *mut u8,
        dw_flags: u32,
    ) -> i32;

    fn CryptCATAdminCalcHashFromFileHandle2(
        h_cat_admin: isize,
        h_file: *mut c_void,
        pcb_hash: *mut u32,
        pb_hash: *mut u8,
        dw_flags: u32,
    ) -> i32;

    fn CryptCATAdminEnumCatalogFromHash(
        h_cat_admin: isize,
        pb_hash: *const u8,
        cb_hash: u32,
        dw_flags: u32,
        ph_prev_cat_info: *mut isize,
    ) -> isize;

    fn CryptCATCatalogInfoFromContext(
        h_cat_info: isize,
        ps_cat_info: *mut CATALOG_INFO,
        dw_flags: u32,
    ) -> i32;

    fn CryptCATAdminReleaseCatalogContext(h_cat_admin: isize, h_cat_info: isize, dw_flags: u32)
        -> i32;

    fn CryptCATAdminReleaseContext(h_cat_admin: isize, dw_flags: u32) -> i32;
}

#[link(name = "crypt32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn CryptQueryObject(
        dw_object_type: u32,
        pv_object: *const c_void,
        dw_expected_content_type_flags: u32,
        dw_expected_format_type_flags: u32,
        dw_flags: u32,
        pdw_msg_and_cert_encoding_type: *mut u32,
        pdw_content_type: *mut u32,
        pdw_format_type: *mut u32,
        ph_cert_store: *mut *mut c_void,
        ph_msg: *mut *mut c_void,
        ppv_context: *mut *mut c_void,
    ) -> i32;

    fn CryptMsgGetParam(
        h_crypt_msg: *const c_void,
        dw_param_type: u32,
        dw_index: u32,
        pv_data: *mut c_void,
        pcb_data: *mut u32,
    ) -> i32;

    fn CryptMsgClose(h_crypt_msg: *const c_void) -> i32;

    fn CertFindCertificateInStore(
        h_cert_store: *mut c_void,
        dw_cert_encoding_type: u32,
        dw_find_flags: u32,
        dw_find_type: u32,
        pv_find_para: *const c_void,
        p_prev_cert_context: *const CERT_CONTEXT,
    ) -> *const CERT_CONTEXT;

    fn CertGetNameStringW(
        p_cert_context: *const CERT_CONTEXT,
        dw_type: u32,
        dw_flags: u32,
        pv_type_para: *const c_void,
        psz_name_string: *mut u16,
        cch_name_string: u32,
    ) -> u32;

    fn CertGetCertificateContextProperty(
        p_cert_context: *const CERT_CONTEXT,
        dw_prop_id: u32,
        pv_data: *mut c_void,
        pcb_data: *mut u32,
    ) -> i32;

    fn CertFreeCertificateContext(p_cert_context: *const CERT_CONTEXT) -> i32;

    fn CertCloseStore(h_cert_store: *mut c_void, dw_flags: u32) -> i32;

    fn CertGetCertificateChain(
        h_chain_engine: *mut c_void,
        p_cert_context: *const CERT_CONTEXT,
        p_time: *const FILETIME,
        h_additional_store: *mut c_void,
        p_chain_para: *const CERT_CHAIN_PARA,
        dw_flags: u32,
        pv_reserved: *const c_void,
        pp_chain_context: *mut *const CERT_CHAIN_CONTEXT,
    ) -> i32;

    fn CertFreeCertificateChain(p_chain_context: *const CERT_CHAIN_CONTEXT);
}
