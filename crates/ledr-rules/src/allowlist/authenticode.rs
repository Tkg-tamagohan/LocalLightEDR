//! Windows Authenticode signature and catalog verification (`WinVerifyTrust` + `CryptQueryObject`).

use std::ffi::c_void;
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;

use ledr_proto::AuthenticodeInfo;

use super::ffi::*;

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
