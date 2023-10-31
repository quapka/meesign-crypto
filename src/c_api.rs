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
    Gg18,
    Elgamal,
    Frost,
    Ptsrsap1,
}

#[repr(C)]
pub enum Recipient {
    Unknown,
    Card,
    Server,
}

impl From<protocol::Recipient> for Recipient {
    fn from(value: protocol::Recipient) -> Self {
        match value {
            protocol::Recipient::Card => Recipient::Card,
            protocol::Recipient::Server => Recipient::Server,
        }
    }
}

#[repr(C)]
pub struct Buffer {
    ptr: *mut u8,
    len: usize,
    rec: Recipient,
}

impl Buffer {
    pub fn from_vec(vec: Vec<u8>, rec: Recipient) -> Self {
        let mut mem = std::mem::ManuallyDrop::new(vec.into_boxed_slice());
        Self {
            ptr: mem.as_mut_ptr(),
            len: mem.len(),
            rec,
        }
    }
}

impl From<Vec<u8>> for Buffer {
    fn from(vec: Vec<u8>) -> Self {
        Buffer::from_vec(vec, Recipient::Unknown)
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe { drop(Box::from_raw(slice::from_raw_parts_mut(self.ptr, self.len))) }
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

// TODO: consider "thin trait objects" or alternatives
pub struct Protocol {
    instance: Box<dyn protocol::Protocol>,
}

impl Protocol {
    fn wrap(instance: Box<dyn protocol::Protocol>) -> *mut Self {
        Box::into_raw(Box::new(Protocol { instance }))
    }
}

#[cfg(feature = "protocol")]
#[no_mangle]
pub unsafe extern "C" fn protocol_serialize(proto_ptr: *mut Protocol) -> Buffer {
    let proto = unsafe { Box::from_raw(proto_ptr) };
    serde_json::to_vec(&proto.instance).unwrap().into()
}

#[cfg(feature = "protocol")]
#[no_mangle]
pub unsafe extern "C" fn protocol_deserialize(ctx_ptr: *const u8, ctx_len: usize) -> *mut Protocol {
    let ser = unsafe { slice::from_raw_parts(ctx_ptr, ctx_len) };
    Protocol::wrap(serde_json::from_slice(ser).unwrap())
}

#[cfg(feature = "protocol")]
#[no_mangle]
pub unsafe extern "C" fn protocol_keygen(proto_id: ProtocolId, with_card: bool) -> *mut Protocol {
    Protocol::wrap(match (proto_id, with_card) {
        #[cfg(feature = "gg18")]
        (ProtocolId::Gg18, false) => Box::new(gg18::KeygenContext::new()),
        #[cfg(feature = "elgamal")]
        (ProtocolId::Elgamal, false) => Box::new(elgamal::KeygenContext::new()),
        #[cfg(feature = "frost")]
        (ProtocolId::Frost, false) => Box::new(frost::KeygenContext::new()),
        #[cfg(feature = "frost")]
        (ProtocolId::Frost, true) => Box::new(frost::KeygenContext::with_card()),
        #[cfg(feature = "ptsrsap1")]
        (ProtocolId::Ptsrsap1, false) => Box::new(ptsrsap1::KeygenContext::new()),
        _ => panic!("Protocol not supported"),
    })
}

#[cfg(feature = "protocol")]
#[no_mangle]
pub unsafe extern "C" fn protocol_advance(
    proto_ptr: *mut Protocol,
    data_ptr: *const u8,
    data_len: usize,
    error_out: *mut *mut c_char,
) -> Buffer {
    let data_in = unsafe { slice::from_raw_parts(data_ptr, data_len) };
    let proto = unsafe { &mut *proto_ptr };

    let (vec, rec) = match proto.instance.advance(data_in) {
        Ok((vec, rec)) => (vec, rec.into()),
        Err(error) => {
            set_error(error_out, &*error);
            (vec![], Recipient::Unknown)
        }
    };
    Buffer::from_vec(vec, rec)
}

#[cfg(feature = "protocol")]
#[no_mangle]
pub unsafe extern "C" fn protocol_finish(
    proto_ptr: *mut Protocol,
    error_out: *mut *mut c_char,
) -> Buffer {
    let proto = unsafe { Box::from_raw(proto_ptr) };

    match proto.instance.finish() {
        Ok(data_out) => data_out,
        Err(error) => {
            set_error(error_out, &*error);
            vec![]
        }
    }
    .into()
}

#[cfg(feature = "protocol")]
#[no_mangle]
pub unsafe extern "C" fn protocol_init(
    // TODO: proto_id should be inferred from group
    proto_id: ProtocolId,
    group_ptr: *const u8,
    group_len: usize,
) -> *mut Protocol {
    let group_ser = unsafe { slice::from_raw_parts(group_ptr, group_len) };

    Protocol::wrap(match proto_id {
        #[cfg(feature = "gg18")]
        ProtocolId::Gg18 => Box::new(gg18::SignContext::new(group_ser)),
        #[cfg(feature = "elgamal")]
        ProtocolId::Elgamal => Box::new(elgamal::DecryptContext::new(group_ser)),
        #[cfg(feature = "frost")]
        ProtocolId::Frost => Box::new(frost::SignContext::new(group_ser)),
        #[cfg(feature = "ptsrsap1")]
        ProtocolId::Ptsrsap1 => Box::new(ptsrsap1::SignContext::new(group_ser)),
        #[cfg(not(all(
            feature = "gg18",
            feature = "elgamal",
            feature = "frost",
            feature = "ptsrsap1"
        )))]
        _ => panic!("Protocol not supported"),
    })
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
