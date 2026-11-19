//! Win32 FFI bindings (`wintrust.dll` & `crypt32.dll`).

use std::ffi::c_void;

pub(super) const WTD_UI_NONE: u32 = 2;
pub(super) const WTD_REVOKE_NONE: u32 = 0;
pub(super) const WTD_CHOICE_FILE: u32 = 1;
pub(super) const WTD_CHOICE_CATALOG: u32 = 2;
pub(super) const WTD_STATEACTION_VERIFY: u32 = 1;
pub(super) const WTD_STATEACTION_CLOSE: u32 = 2;
pub(super) const WTD_REVOCATION_CHECK_NONE: u32 = 0x0010;
pub(super) const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x1000;

pub(super) const CERT_QUERY_OBJECT_FILE: u32 = 1;
pub(super) const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED: u32 = 256;
pub(super) const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED: u32 = 1024;
pub(super) const CERT_QUERY_FORMAT_FLAG_ALL: u32 = 14;
pub(super) const CMSG_SIGNER_INFO_PARAM: u32 = 6;
pub(super) const X509_ASN_ENCODING: u32 = 1;
pub(super) const PKCS_7_ASN_ENCODING: u32 = 0x0001_0000;
pub(super) const CERT_FIND_SUBJECT_CERT: u32 = 720_896;
pub(super) const CERT_NAME_RDN_TYPE: u32 = 2;
pub(super) const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
pub(super) const CERT_X500_NAME_STR: u32 = 3;
pub(super) const CERT_NAME_STR_REVERSE_FLAG: u32 = 0x0200_0000;
pub(super) const CERT_SHA1_HASH_PROP_ID: u32 = 3;
pub(super) const CERT_CHAIN_CACHE_END_CERT: u32 = 1;

#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct GUID {
    pub(super) data1: u32,
    pub(super) data2: u16,
    pub(super) data3: u16,
    pub(super) data4: [u8; 8],
}

pub(super) const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID = GUID {
    data1: 0x00AA_C56B,
    data2: 0xCD44,
    data3: 0x11D0,
    data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};

#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct FILETIME {
    pub(super) dw_low_date_time: u32,
    pub(super) dw_high_date_time: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRYPTOAPI_BLOB {
    pub(super) cb_data: u32,
    pub(super) pb_data: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRYPT_BIT_BLOB {
    pub(super) cb_data: u32,
    pub(super) pb_data: *mut u8,
    pub(super) c_unused_bits: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRYPT_ALGORITHM_IDENTIFIER {
    pub(super) psz_obj_id: *mut u8,
    pub(super) parameters: CRYPTOAPI_BLOB,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CRYPT_ATTRIBUTES {
    pub(super) c_attr: u32,
    pub(super) rg_attr: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CMSG_SIGNER_INFO {
    pub(super) dw_version: u32,
    pub(super) issuer: CRYPTOAPI_BLOB,
    pub(super) serial_number: CRYPTOAPI_BLOB,
    pub(super) hash_algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub(super) hash_encryption_algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub(super) encrypted_hash: CRYPTOAPI_BLOB,
    pub(super) auth_attrs: CRYPT_ATTRIBUTES,
    pub(super) unauth_attrs: CRYPT_ATTRIBUTES,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_PUBLIC_KEY_INFO {
    pub(super) algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub(super) public_key: CRYPT_BIT_BLOB,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_INFO {
    pub(super) dw_version: u32,
    pub(super) serial_number: CRYPTOAPI_BLOB,
    pub(super) signature_algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub(super) issuer: CRYPTOAPI_BLOB,
    pub(super) not_before: FILETIME,
    pub(super) not_after: FILETIME,
    pub(super) subject: CRYPTOAPI_BLOB,
    pub(super) subject_public_key_info: CERT_PUBLIC_KEY_INFO,
    pub(super) issuer_unique_id: CRYPT_BIT_BLOB,
    pub(super) subject_unique_id: CRYPT_BIT_BLOB,
    pub(super) c_extension: u32,
    pub(super) rg_extension: *mut c_void,
}

#[repr(C)]
pub(super) struct CERT_CONTEXT {
    pub(super) dw_cert_encoding_type: u32,
    pub(super) pb_cert_encoded: *mut u8,
    pub(super) cb_cert_encoded: u32,
    pub(super) p_cert_info: *mut CERT_INFO,
    pub(super) h_cert_store: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_TRUST_STATUS {
    pub(super) dw_error_status: u32,
    pub(super) dw_info_status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_USAGE_MATCH {
    pub(super) dw_type: u32,
    pub(super) c_usage_identifier: u32,
    pub(super) rgpsz_usage_identifier: *mut *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CERT_CHAIN_PARA {
    pub(super) cb_size: u32,
    pub(super) requested_usage: CERT_USAGE_MATCH,
    pub(super) requested_issuance_policy: CERT_USAGE_MATCH,
    pub(super) dw_url_retrieval_timeout: u32,
    pub(super) f_check_revocation_freshness_time: i32,
    pub(super) dw_revocation_freshness_time: u32,
    pub(super) pft_cache_resync: *mut FILETIME,
    pub(super) p_strong_sign_para: *mut c_void,
    pub(super) dw_strong_sign_flags: u32,
}

#[repr(C)]
pub(super) struct CERT_CHAIN_ELEMENT {
    pub(super) cb_size: u32,
    pub(super) p_cert_context: *const CERT_CONTEXT,
    pub(super) trust_status: CERT_TRUST_STATUS,
}

#[repr(C)]
pub(super) struct CERT_SIMPLE_CHAIN {
    pub(super) cb_size: u32,
    pub(super) trust_status: CERT_TRUST_STATUS,
    pub(super) c_element: u32,
    pub(super) rgp_element: *mut *mut CERT_CHAIN_ELEMENT,
}

#[repr(C)]
pub(super) struct CERT_CHAIN_CONTEXT {
    pub(super) cb_size: u32,
    pub(super) trust_status: CERT_TRUST_STATUS,
    pub(super) c_chain: u32,
    pub(super) rgp_chain: *mut *mut CERT_SIMPLE_CHAIN,
}

#[repr(C)]
pub(super) struct WINTRUST_FILE_INFO {
    pub(super) cb_struct: u32,
    pub(super) pcwsz_file_path: *const u16,
    pub(super) h_file: *mut c_void,
    pub(super) pg_known_subject: *mut GUID,
}

#[repr(C)]
pub(super) struct WINTRUST_CATALOG_INFO {
    pub(super) cb_struct: u32,
    pub(super) dw_catalog_version: u32,
    pub(super) pcwsz_catalog_file_path: *const u16,
    pub(super) pcwsz_member_tag: *const u16,
    pub(super) pcwsz_member_file_path: *const u16,
    pub(super) h_member_file: *mut c_void,
    pub(super) pb_calculated_file_hash: *mut u8,
    pub(super) cb_calculated_file_hash: u32,
    pub(super) pc_catalog_context: *mut c_void,
    pub(super) h_cat_admin: isize,
}

#[repr(C)]
pub(super) union WINTRUST_DATA_CHOICE {
    pub(super) p_file: *mut WINTRUST_FILE_INFO,
    pub(super) p_catalog: *mut WINTRUST_CATALOG_INFO,
}

#[repr(C)]
pub(super) struct WINTRUST_DATA {
    pub(super) cb_struct: u32,
    pub(super) p_policy_callback_data: *mut c_void,
    pub(super) p_sip_client_data: *mut c_void,
    pub(super) dw_ui_choice: u32,
    pub(super) fdw_revocation_checks: u32,
    pub(super) dw_union_choice: u32,
    pub(super) choice: WINTRUST_DATA_CHOICE,
    pub(super) dw_state_action: u32,
    pub(super) h_wvt_state_data: *mut c_void,
    pub(super) pwsz_url_reference: *mut u16,
    pub(super) dw_prov_flags: u32,
    pub(super) dw_ui_context: u32,
    pub(super) p_signature_settings: *mut c_void,
}

#[repr(C)]
pub(super) struct CATALOG_INFO {
    pub(super) cb_struct: u32,
    pub(super) wsz_catalog_file: [u16; 260],
}

#[link(name = "wintrust.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    pub(super) fn WinVerifyTrust(hwnd: *mut c_void, pg_action_id: *mut GUID, p_wvt_data: *mut c_void) -> i32;

    pub(super) fn CryptCATAdminAcquireContext(
        ph_cat_admin: *mut isize,
        pg_subsystem: *const GUID,
        dw_flags: u32,
    ) -> i32;

    pub(super) fn CryptCATAdminAcquireContext2(
        ph_cat_admin: *mut isize,
        pg_subsystem: *const GUID,
        pwsz_hash_algorithm: *const u16,
        p_strong_hash_policy: *const c_void,
        dw_flags: u32,
    ) -> i32;

    pub(super) fn CryptCATAdminCalcHashFromFileHandle(
        h_file: *mut c_void,
        pcb_hash: *mut u32,
        pb_hash: *mut u8,
        dw_flags: u32,
    ) -> i32;

    pub(super) fn CryptCATAdminCalcHashFromFileHandle2(
        h_cat_admin: isize,
        h_file: *mut c_void,
        pcb_hash: *mut u32,
        pb_hash: *mut u8,
        dw_flags: u32,
    ) -> i32;

    pub(super) fn CryptCATAdminEnumCatalogFromHash(
        h_cat_admin: isize,
        pb_hash: *const u8,
        cb_hash: u32,
        dw_flags: u32,
        ph_prev_cat_info: *mut isize,
    ) -> isize;

    pub(super) fn CryptCATCatalogInfoFromContext(
        h_cat_info: isize,
        ps_cat_info: *mut CATALOG_INFO,
        dw_flags: u32,
    ) -> i32;

    pub(super) fn CryptCATAdminReleaseCatalogContext(h_cat_admin: isize, h_cat_info: isize, dw_flags: u32)
        -> i32;

    pub(super) fn CryptCATAdminReleaseContext(h_cat_admin: isize, dw_flags: u32) -> i32;
}

#[link(name = "crypt32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    pub(super) fn CryptQueryObject(
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

    pub(super) fn CryptMsgGetParam(
        h_crypt_msg: *const c_void,
        dw_param_type: u32,
        dw_index: u32,
        pv_data: *mut c_void,
        pcb_data: *mut u32,
    ) -> i32;

    pub(super) fn CryptMsgClose(h_crypt_msg: *const c_void) -> i32;

    pub(super) fn CertFindCertificateInStore(
        h_cert_store: *mut c_void,
        dw_cert_encoding_type: u32,
        dw_find_flags: u32,
        dw_find_type: u32,
        pv_find_para: *const c_void,
        p_prev_cert_context: *const CERT_CONTEXT,
    ) -> *const CERT_CONTEXT;

    pub(super) fn CertGetNameStringW(
        p_cert_context: *const CERT_CONTEXT,
        dw_type: u32,
        dw_flags: u32,
        pv_type_para: *const c_void,
        psz_name_string: *mut u16,
        cch_name_string: u32,
    ) -> u32;

    pub(super) fn CertGetCertificateContextProperty(
        p_cert_context: *const CERT_CONTEXT,
        dw_prop_id: u32,
        pv_data: *mut c_void,
        pcb_data: *mut u32,
    ) -> i32;

    pub(super) fn CertFreeCertificateContext(p_cert_context: *const CERT_CONTEXT) -> i32;

    pub(super) fn CertCloseStore(h_cert_store: *mut c_void, dw_flags: u32) -> i32;

    pub(super) fn CertGetCertificateChain(
        h_chain_engine: *mut c_void,
        p_cert_context: *const CERT_CONTEXT,
        p_time: *const FILETIME,
        h_additional_store: *mut c_void,
        p_chain_para: *const CERT_CHAIN_PARA,
        dw_flags: u32,
        pv_reserved: *const c_void,
        pp_chain_context: *mut *const CERT_CHAIN_CONTEXT,
    ) -> i32;

    pub(super) fn CertFreeCertificateChain(p_chain_context: *const CERT_CHAIN_CONTEXT);
}
