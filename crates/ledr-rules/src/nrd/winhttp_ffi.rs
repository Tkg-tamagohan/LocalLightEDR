//! WinHTTP `raw-dylib` FFI declarations.

use std::ffi::c_void;

pub const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: u32 = 0;
pub const WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY: u32 = 4;
pub const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;
pub const WINHTTP_FLAG_ASYNC: u32 = 0x1000_0000;
pub const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
pub const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x2000_0000;
pub const WINHTTP_OPTION_CONTEXT_VALUE: u32 = 45;
pub const WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS: u32 = 0xFFFF_FFFF;
pub const WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING: u32 = 0x0000_0800;
pub const WINHTTP_CALLBACK_STATUS_SECURE_FAILURE: u32 = 0x0001_0000;
pub const WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE: u32 = 0x0002_0000;
pub const WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE: u32 = 0x0004_0000;
pub const WINHTTP_CALLBACK_STATUS_READ_COMPLETE: u32 = 0x0008_0000;
pub const WINHTTP_CALLBACK_STATUS_REQUEST_ERROR: u32 = 0x0020_0000;
pub const WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE: u32 = 0x0040_0000;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WinHttpAsyncResult {
    pub dw_result: usize,
    pub dw_error: u32,
}

pub type WinHttpStatusCallback = Option<
    unsafe extern "system" fn(
        h_internet: *mut c_void,
        dw_context: usize,
        dw_internet_status: u32,
        lpv_status_information: *mut c_void,
        dw_status_information_length: u32,
    ),
>;

#[link(name = "winhttp.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    pub fn WinHttpOpen(
        psz_agent_w: *const u16,
        dw_access_type: u32,
        psz_proxy_w: *const u16,
        psz_proxy_bypass_w: *const u16,
        dw_flags: u32,
    ) -> *mut c_void;
    pub fn WinHttpSetTimeouts(
        h_internet: *mut c_void,
        n_resolve_timeout: i32,
        n_connect_timeout: i32,
        n_send_timeout: i32,
        n_receive_timeout: i32,
    ) -> i32;
    pub fn WinHttpConnect(
        h_session: *mut c_void,
        pswz_server_name: *const u16,
        n_server_port: u16,
        dw_reserved: u32,
    ) -> *mut c_void;
    pub fn WinHttpOpenRequest(
        h_connect: *mut c_void,
        pwsz_verb: *const u16,
        pwsz_object_name: *const u16,
        pwsz_version: *const u16,
        pwsz_referrer: *const u16,
        ppwsz_accept_types: *const *const u16,
        dw_flags: u32,
    ) -> *mut c_void;
    pub fn WinHttpSetOption(
        h_internet: *mut c_void,
        dw_option: u32,
        lp_buffer: *const c_void,
        dw_buffer_length: u32,
    ) -> i32;
    pub fn WinHttpSetStatusCallback(
        h_internet: *mut c_void,
        lpfn_internet_callback: WinHttpStatusCallback,
        dw_notification_flags: u32,
        dw_reserved: usize,
    ) -> *mut c_void;
    pub fn WinHttpSendRequest(
        h_request: *mut c_void,
        lpsz_headers: *const u16,
        dw_headers_length: u32,
        lp_optional: *mut c_void,
        dw_optional_length: u32,
        dw_total_length: u32,
        dw_context: usize,
    ) -> i32;
    pub fn WinHttpReceiveResponse(h_request: *mut c_void, lp_reserved: *mut c_void) -> i32;
    pub fn WinHttpQueryHeaders(
        h_request: *mut c_void,
        dw_info_level: u32,
        pwsz_name: *const u16,
        lp_buffer: *mut c_void,
        lpdw_buffer_length: *mut u32,
        lpdw_index: *mut u32,
    ) -> i32;
    pub fn WinHttpQueryDataAvailable(
        h_request: *mut c_void,
        lpdw_number_of_bytes_available: *mut u32,
    ) -> i32;
    pub fn WinHttpReadData(
        h_request: *mut c_void,
        lp_buffer: *mut c_void,
        dw_number_of_bytes_to_read: u32,
        lpdw_number_of_bytes_read: *mut u32,
    ) -> i32;
    pub fn WinHttpCloseHandle(h_internet: *mut c_void) -> i32;
}
