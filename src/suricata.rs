/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

//! Minimal Suricata 8.0 plugin ABI bindings used by this crate.
//!
//! These declarations intentionally mirror only the structs, fields, constants,
//! and functions required by the nDPI plugin. Keep the offsets in the padded
//! structs in sync with Suricata 8.0.x.

#![allow(dead_code)]
#![allow(non_snake_case)]

use core::ffi::c_void;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_uint};

pub const SC_API_VERSION: u64 = 0x0800;
pub const SC_PACKAGE_VERSION: &[u8] = b"8.0.x\0";

pub const SC_LOG_ERROR: c_int = 2;
pub const SC_LOG_NOTICE: c_int = 5;

pub const IPV6_HEADER_LEN: u16 = 40;
pub const DETECT_SM_LIST_MATCH: c_int = 0;
pub const DETECT_SM_LIST_MAX: usize = 7;
pub const SIGMATCH_QUOTES_OPTIONAL: u16 = 1 << 5;
pub const SIGMATCH_HANDLE_NEGATION: u16 = 1 << 7;

pub const PACKET_L3_IPV4: c_int = 1;
pub const PACKET_L3_IPV6: c_int = 2;

pub const IPPROTO_UDP: u8 = 17;

#[repr(C)]
pub struct SCPlugin {
    pub version: u64,
    pub suricata_version: *const c_char,
    pub name: *const c_char,
    pub plugin_version: *const c_char,
    pub license: *const c_char,
    pub author: *const c_char,
    pub Init: Option<unsafe extern "C" fn()>,
}

unsafe impl Sync for SCPlugin {}

#[repr(C)]
pub struct IPV4Hdr {
    pub ip_verhl: u8,
    pub ip_tos: u8,
    pub ip_len: u16,
    pub ip_id: u16,
    pub ip_off: u16,
    pub ip_ttl: u8,
    pub ip_proto: u8,
    pub ip_csum: u16,
    pub ip_addrs: [u16; 4],
}

#[repr(C)]
pub struct IPV6Hdr {
    pub ip6_un1_flow: u32,
    pub ip6_un1_plen: u16,
    pub ip6_un1_nxt: u8,
    pub ip6_un1_hlim: u8,
    pub ip6_addrs: [u16; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PacketL3Hdrs {
    pub ip4h: *const IPV4Hdr,
    pub ip6h: *const IPV6Hdr,
    pub ptr: *const c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PacketL3Vars {
    pub bytes: [u8; 24],
}

#[repr(C)]
pub struct PacketL3 {
    pub type_: c_int,
    pub csum_set: bool,
    pub csum: u16,
    pub hdrs: PacketL3Hdrs,
    pub vars: PacketL3Vars,
}

#[repr(C)]
pub struct Packet {
    pub _pad_proto: [u8; 44],
    pub proto: u8,
    pub _pad_flow: [u8; 19],
    pub flow: *mut Flow,
    pub _pad_ts: [u8; 8],
    pub ts: u64,
    pub _pad_l3: [u8; 104],
    pub l3: PacketL3,
    pub _pad_pcap_cnt: [u8; 144],
    pub pcap_cnt: u64,
}

impl Packet {
    pub unsafe fn ip_packet(&self) -> Option<(*const u8, u16)> {
        match self.l3.type_ {
            PACKET_L3_IPV4 => {
                let ip4h = self.l3.hdrs.ip4h;
                if ip4h.is_null() {
                    None
                } else {
                    Some((ip4h.cast(), u16::from_be((*ip4h).ip_len)))
                }
            }
            PACKET_L3_IPV6 => {
                let ip6h = self.l3.hdrs.ip6h;
                if ip6h.is_null() {
                    None
                } else {
                    Some((
                        ip6h.cast(),
                        IPV6_HEADER_LEN + u16::from_be((*ip6h).ip6_un1_plen),
                    ))
                }
            }
            _ => None,
        }
    }

    pub fn timestamp_millis(&self) -> u64 {
        /* SCTime_t is a uint64_t split into secs:44 and usecs:20 bitfields. */
        let secs = self.ts & ((1u64 << 44) - 1);
        let usecs = self.ts >> 44;
        secs * 1000 + usecs / 1000
    }
}

#[repr(C)]
pub struct Flow {
    pub _pad_proto: [u8; 38],
    pub proto: u8,
    pub _pad_counters: [u8; 209],
    pub todstpktcnt: u32,
    pub tosrcpktcnt: u32,
}

#[repr(C)]
pub struct ThreadVars {
    _private: [u8; 0],
}

#[repr(C)]
pub struct DetectEngineCtx {
    _private: [u8; 0],
}

#[repr(C)]
pub struct DetectEngineThreadCtx {
    _private: [u8; 0],
}

#[repr(C)]
pub struct SigMatchCtx {
    _private: [u8; 0],
}

#[repr(C)]
pub struct SigMatch {
    pub type_: u16,
    pub idx: u16,
    pub ctx: *mut SigMatchCtx,
    pub next: *mut SigMatch,
    pub prev: *mut SigMatch,
}

#[repr(C)]
pub struct SignatureInitData {
    pub _pad_negated: [u8; 18],
    pub negated: bool,
    pub _pad_smlists: [u8; 365],
    pub smlists: [*mut SigMatch; DETECT_SM_LIST_MAX],
}

#[repr(C)]
pub struct Signature {
    pub _pad_init_data: [u8; 264],
    pub init_data: *mut SignatureInitData,
}

pub type MatchFn = Option<
    unsafe extern "C" fn(
        *mut DetectEngineThreadCtx,
        *mut Packet,
        *const Signature,
        *const SigMatchCtx,
    ) -> c_int,
>;
pub type AppLayerTxMatchFn = Option<
    unsafe extern "C" fn(
        *mut DetectEngineThreadCtx,
        *mut Flow,
        u8,
        *mut c_void,
        *mut c_void,
        *const Signature,
        *const SigMatchCtx,
    ) -> c_int,
>;
pub type FileMatchFn = Option<
    unsafe extern "C" fn(
        *mut DetectEngineThreadCtx,
        *mut Flow,
        u8,
        *mut c_void,
        *const Signature,
        *const SigMatchCtx,
    ) -> c_int,
>;

#[repr(C)]
pub struct SigTableElmt {
    pub Match: MatchFn,
    pub AppLayerTxMatch: AppLayerTxMatchFn,
    pub FileMatch: FileMatchFn,
    pub Transform:
        Option<unsafe extern "C" fn(*mut DetectEngineThreadCtx, *mut c_void, *mut c_void)>,
    pub TransformValidate: Option<unsafe extern "C" fn(*const u8, u16, *mut c_void) -> bool>,
    pub TransformId: Option<unsafe extern "C" fn(*mut *const u8, *mut u32, *mut c_void)>,
    pub Setup:
        Option<unsafe extern "C" fn(*mut DetectEngineCtx, *mut Signature, *const c_char) -> c_int>,
    pub SupportsPrefilter: Option<unsafe extern "C" fn(*const Signature) -> bool>,
    pub SetupPrefilter: Option<unsafe extern "C" fn(*mut DetectEngineCtx, *mut c_void) -> c_int>,
    pub Free: Option<unsafe extern "C" fn(*mut DetectEngineCtx, *mut c_void)>,
    pub flags: u16,
    pub tables: u8,
    pub alternative: u16,
    pub name: *const c_char,
    pub alias: *const c_char,
    pub desc: *const c_char,
    pub url: *const c_char,
    pub Cleanup: Option<unsafe extern "C" fn(*mut SigTableElmt)>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FlowStorageId {
    pub id: c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ThreadStorageId {
    pub id: c_int,
}

#[repr(C)]
pub struct SCJsonBuilder {
    _private: [u8; 0],
}

pub unsafe fn scjb_set_formatted(jb: *mut SCJsonBuilder, formatted: *const c_char) -> bool {
    SCJbSetFormatted(jb, formatted)
}

pub fn log_message(level: c_int, file: &str, line: u32, function: &str, message: String) {
    unsafe {
        let file = safe_cstring(file);
        let function = safe_cstring(function);
        let message = safe_cstring(&message);
        let module = b"ndpi-plugin\0";
        let fmt = b"%s\0";

        if level == SC_LOG_ERROR {
            SCLogErr(
                level,
                file.as_ptr(),
                function.as_ptr(),
                line as c_int,
                module.as_ptr().cast(),
                fmt.as_ptr().cast(),
                message.as_ptr(),
            );
        } else {
            SCLog(
                level,
                file.as_ptr(),
                function.as_ptr(),
                line as c_int,
                module.as_ptr().cast(),
                fmt.as_ptr().cast(),
                message.as_ptr(),
            );
        }
    }
}

pub fn fatal_error(message: String) -> ! {
    log_message(SC_LOG_ERROR, file!(), line!(), "fatal_error", message);
    std::process::exit(1);
}

fn safe_cstring(val: &str) -> CString {
    let mut safe = Vec::with_capacity(val.len());
    for c in val.as_bytes() {
        if *c != 0 {
            safe.push(*c);
        }
    }
    CString::new(safe).unwrap_or_else(|_| CString::new("<failed to encode string>").unwrap())
}

pub type FlowInitCallback =
    Option<unsafe extern "C" fn(*mut ThreadVars, *mut Flow, *const Packet, *mut c_void)>;
pub type FlowUpdateCallback =
    Option<unsafe extern "C" fn(*mut ThreadVars, *mut Flow, *mut Packet, *mut c_void)>;
pub type FlowFinishCallback = Option<unsafe extern "C" fn(*mut ThreadVars, *mut Flow, *mut c_void)>;
pub type ThreadInitCallback = Option<unsafe extern "C" fn(*mut ThreadVars, *mut c_void)>;
pub type EveCallback = Option<
    unsafe extern "C" fn(
        *mut ThreadVars,
        *const Packet,
        *mut Flow,
        *mut SCJsonBuilder,
        *mut c_void,
    ),
>;

extern "C" {
    pub static mut sigmatch_table: *mut SigTableElmt;

    pub fn SCLog(
        level: c_int,
        file: *const c_char,
        func: *const c_char,
        line: c_int,
        module: *const c_char,
        fmt: *const c_char,
        ...
    );
    pub fn SCLogErr(
        level: c_int,
        file: *const c_char,
        func: *const c_char,
        line: c_int,
        module: *const c_char,
        fmt: *const c_char,
        ...
    );

    pub fn FlowStorageRegister(
        name: *const c_char,
        size: c_uint,
        Alloc: Option<unsafe extern "C" fn(c_uint) -> *mut c_void>,
        Free: Option<unsafe extern "C" fn(*mut c_void)>,
    ) -> FlowStorageId;
    pub fn FlowGetStorageById(f: *const Flow, id: FlowStorageId) -> *mut c_void;
    pub fn FlowSetStorageById(f: *mut Flow, id: FlowStorageId, ptr: *mut c_void) -> c_int;

    pub fn ThreadStorageRegister(
        name: *const c_char,
        size: c_uint,
        Alloc: Option<unsafe extern "C" fn(c_uint) -> *mut c_void>,
        Free: Option<unsafe extern "C" fn(*mut c_void)>,
    ) -> ThreadStorageId;
    pub fn ThreadGetStorageById(tv: *const ThreadVars, id: ThreadStorageId) -> *mut c_void;
    pub fn ThreadSetStorageById(
        tv: *mut ThreadVars,
        id: ThreadStorageId,
        ptr: *mut c_void,
    ) -> c_int;

    pub fn SCFlowRegisterInitCallback(fn_: FlowInitCallback, user: *mut c_void) -> bool;
    pub fn SCFlowRegisterUpdateCallback(fn_: FlowUpdateCallback, user: *mut c_void) -> bool;
    pub fn SCFlowRegisterFinishCallback(fn_: FlowFinishCallback, user: *mut c_void) -> bool;
    pub fn SCThreadRegisterInitCallback(fn_: ThreadInitCallback, user: *mut c_void) -> bool;
    pub fn SCEveRegisterCallback(fn_: EveCallback, user: *mut c_void) -> bool;

    pub fn SCJbSetFormatted(jb: *mut SCJsonBuilder, formatted: *const c_char) -> bool;

    pub fn SCSigMatchAppendSMToList(
        de_ctx: *mut DetectEngineCtx,
        s: *mut Signature,
        type_: u16,
        ctx: *mut SigMatchCtx,
        list: c_int,
    ) -> *mut SigMatch;
    pub fn SCDetectHelperNewKeywordId() -> c_int;
}
