mod bindings {
    #![allow(unknown_lints)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(non_upper_case_globals)]
    #![allow(unsafe_op_in_unsafe_fn)]
    #![allow(unnecessary_transmutes)]
    #![allow(clippy::all)]

    include!("bindings.rs");
}

pub use bindings::*;
