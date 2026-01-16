//! FCP2 protocol framing and session primitives (`FCPS`/`FCPC`).

#![forbid(unsafe_code)]

mod fcpc;
mod fcps;
mod session;
mod symbol_envelope;

pub use fcpc::*;
pub use fcps::*;
pub use session::*;
pub use symbol_envelope::*;
