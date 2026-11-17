//! `nsvault` library and C ABI.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod api;
pub mod cli;
pub mod commands;
pub mod error;
#[allow(unsafe_code)]
pub mod ffi;
pub mod secret;

mod config;
mod key;
mod provider;
mod shell;

pub use api::Client;
pub use error::{Error, Result};
pub use provider::{EnsureStatus, ListedKey};
pub use secret::Secret;
