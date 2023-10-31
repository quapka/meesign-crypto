use core::slice;
use std::error::Error;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;

use crate::auth;
#[cfg(feature = "elgamal")]
use crate::protocol::elgamal;
#[cfg(feature = "frost")]
use crate::protocol::frost;
#[cfg(feature = "gg18")]
use crate::protocol::gg18;
#[cfg(feature = "ptsrsap1")]
use crate::protocol::ptsrsap1;
#[cfg(feature = "protocol")]
use crate::protocol::{self, KeygenProtocol, ThresholdProtocol};

#[repr(C)]
pub enum ProtocolId {
    #[cfg(feature = "gg18")]
    Gg18,
    #[cfg(feature = "elgamal")]
    Elgamal,
    #[cfg(feature = "frost")]
    Frost,
    #[cfg(feature = "ptsrsap1")]
    Ptsrsap1,
}

#[repr(C)]
pub struct Buffer {
    ptr: *mut u8,
    len: usize,
    capacity: usize,
}

impl From<Vec<u8>> for Buffer {
    fn from(vec: Vec<u8>) -> Self {
        let mut mem = std::mem::ManuallyDrop::new(vec);
        Self {
            ptr: mem.as_mut_ptr(),
            len: mem.len(),
            capacity: mem.capacity(),
        }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe {
            Vec::from_raw_parts(self.ptr, self.len, self.capacity);
        }
    }
}

#[no_mangle]
#[allow(unused_variables)]
pub unsafe extern "C" fn buffer_free(buffer: Buffer) {}

fn set_error(error_out: *mut *mut c_char, error: &dyn Error) {
    if !error_out.is_null() {
        let msg = CString::new(error.to_string()).unwrap().into_raw();
        unsafe { *error_out = msg };
    }
}

#[no_mangle]
pub unsafe extern "C" fn error_free(error: *mut c_char) {
    if !error.is_null() {
        unsafe {
            let _ = CString::from_raw(error);
        };
    }
}

#[repr(C)]
pub struct ProtocolResult {
    context: Buffer,
    data: Buffer,
}

impl ProtocolResult {
    pub fn new(context: Vec<u8>, data: Vec<u8>) -> Self {
        Self {
            context: context.into(),
            data: data.into(),
        }
    }
}

#[cfg(feature = "protocol")]
#[no_mangle]
#[allow(unused_variables)]
pub unsafe extern "C" fn protocol_result_free(res: ProtocolResult) {}

#[cfg(feature = "protocol")]
#[no_mangle]
pub unsafe extern "C" fn protocol_keygen(proto_id: ProtocolId) -> ProtocolResult {
    let ctx: Box<dyn protocol::Protocol> = match proto_id {
        #[cfg(feature = "gg18")]
        ProtocolId::Gg18 => Box::new(gg18::KeygenContext::new()),
        #[cfg(feature = "elgamal")]
        ProtocolId::Elgamal => Box::new(elgamal::KeygenContext::new()),
        #[cfg(feature = "frost")]
        ProtocolId::Frost => Box::new(frost::KeygenContext::new()),
        // #[cfg(feature = "ptsrsap1")]
        // ProtocolId::Ptsrsap1 => Box::new(),
        #[cfg(not(all(feature = "gg18", feature = "elgamal", feature = "frost")))]
        _ => panic!("Protocol not supported"),
    };
    let ctx_ser = serde_json::to_vec(&ctx).unwrap();
    ProtocolResult::new(ctx_ser, vec![])
}

#[cfg(feature = "protocol")]
fn advance(ctx1_ser: &[u8], data_in: &[u8]) -> protocol::Result<(Vec<u8>, Vec<u8>)> {
    let mut ctx1: Box<dyn protocol::Protocol> = serde_json::from_slice(ctx1_ser).unwrap();
    let data_out = ctx1.advance(data_in)?;
    let ctx2_ser = serde_json::to_vec(&ctx1).unwrap();
    Ok((ctx2_ser, data_out))
}

#[cfg(feature = "protocol")]
#[no_mangle]
pub unsafe extern "C" fn protocol_advance(
    ctx_ptr: *const u8,
    ctx_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    error_out: *mut *mut c_char,
) -> ProtocolResult {
    let ctx_ser = unsafe { slice::from_raw_parts(ctx_ptr, ctx_len) };
    let data_in = unsafe { slice::from_raw_parts(data_ptr, data_len) };

    match advance(ctx_ser, data_in) {
        Ok((ctx_ser, data_out)) => ProtocolResult::new(ctx_ser, data_out),
        Err(error) => {
            set_error(error_out, &*error);
            ProtocolResult::new(vec![], vec![])
        }
    }
}

#[cfg(feature = "protocol")]
fn finish(ctx_ser: &[u8]) -> protocol::Result<(Vec<u8>, Vec<u8>)> {
    let ctx: Box<dyn protocol::Protocol> = serde_json::from_slice(ctx_ser).unwrap();
    let data_out = ctx.finish()?;
    Ok((vec![], data_out))
}

#[cfg(feature = "protocol")]
#[no_mangle]
pub unsafe extern "C" fn protocol_finish(
    ctx_ptr: *const u8,
    ctx_len: usize,
    error_out: *mut *mut c_char,
) -> ProtocolResult {
    let ctx_ser = unsafe { slice::from_raw_parts(ctx_ptr, ctx_len) };

    match finish(ctx_ser) {
        Ok((ctx_ser, data_out)) => ProtocolResult::new(ctx_ser, data_out),
        Err(error) => {
            set_error(error_out, &*error);
            ProtocolResult::new(vec![], vec![])
        }
    }
}

#[cfg(feature = "protocol")]
#[no_mangle]
pub unsafe extern "C" fn protocol_init(
    proto_id: ProtocolId,
    group_ptr: *const u8,
    group_len: usize,
) -> ProtocolResult {
    let group_ser = unsafe { slice::from_raw_parts(group_ptr, group_len) };

    let ctx: Box<dyn protocol::Protocol> = match proto_id {
        #[cfg(feature = "gg18")]
        ProtocolId::Gg18 => Box::new(gg18::SignContext::new(group_ser)),
        #[cfg(feature = "elgamal")]
        ProtocolId::Elgamal => Box::new(elgamal::DecryptContext::new(group_ser)),
        #[cfg(feature = "frost")]
        ProtocolId::Frost => Box::new(frost::SignContext::new(group_ser)),
        #[cfg(feature = "ptsrsap1")]
        // ProtocolId::Ptsrsap1 => Box::new(),
        // #[cfg(not(all(feature = "gg18", feature = "elgamal", feature = "frost")))]
        _ => panic!("Protocol not supported"),
    };
    let ctx_ser = serde_json::to_vec(&ctx).unwrap();

    ProtocolResult::new(ctx_ser, vec![])
}

#[repr(C)]
pub struct AuthKey {
    key: Buffer,
    csr: Buffer,
}

impl AuthKey {
    pub fn new(key: Vec<u8>, csr: Vec<u8>) -> Self {
        Self {
            key: key.into(),
            csr: csr.into(),
        }
    }
}

#[no_mangle]
#[allow(unused_variables)]
pub unsafe extern "C" fn auth_key_free(key: AuthKey) {}

#[no_mangle]
pub unsafe extern "C" fn auth_keygen(name: *const c_char, error_out: *mut *mut c_char) -> AuthKey {
    let name = unsafe { CStr::from_ptr(name) }.to_str().unwrap();
    match auth::gen_key_with_csr(name) {
        Ok((key, csr)) => AuthKey::new(key, csr),
        Err(error) => {
            set_error(error_out, &error);
            AuthKey::new(vec![], vec![])
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn auth_cert_key_to_pkcs12(
    key_ptr: *const u8,
    key_len: usize,
    cert_ptr: *const u8,
    cert_len: usize,
    error_out: *mut *mut c_char,
) -> Buffer {
    let key_der = unsafe { slice::from_raw_parts(key_ptr, key_len) };
    let cert_der = unsafe { slice::from_raw_parts(cert_ptr, cert_len) };

    match auth::cert_key_to_pkcs12(key_der, cert_der) {
        Ok(pkcs12) => pkcs12.into(),
        Err(error) => {
            set_error(error_out, &error);
            vec![].into()
        }
    }
}

#[cfg(feature = "elgamal")]
#[no_mangle]
pub unsafe extern "C" fn encrypt(
    msg_ptr: *const u8,
    msg_len: usize,
    key_ptr: *const u8,
    key_len: usize,
    error_out: *mut *mut c_char,
) -> Buffer {
    let msg = unsafe { slice::from_raw_parts(msg_ptr, msg_len) };
    let key = unsafe { slice::from_raw_parts(key_ptr, key_len) };

    match elgamal::encrypt(msg, key) {
        Ok(ciphertext) => ciphertext.into(),
        Err(error) => {
            set_error(error_out, &*error);
            vec![].into()
        }
    }
}
