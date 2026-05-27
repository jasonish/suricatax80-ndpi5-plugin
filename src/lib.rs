#![allow(non_snake_case)]

mod suricata {
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/suricata_8_bindings.rs"));
}

use core::ffi::c_void;

extern "C" {
    fn NdpiPluginRegister() -> *const c_void;
}

#[no_mangle]
pub extern "C" fn SCPluginRegister() -> *mut suricata::SCPlugin {
    unsafe { NdpiPluginRegister().cast_mut().cast::<suricata::SCPlugin>() }
}
