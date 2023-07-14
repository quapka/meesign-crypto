mod auth;
pub mod c_api;
mod protocol;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/meesign.rs"));
}
