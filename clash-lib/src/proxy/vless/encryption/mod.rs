//! Mihomo-compatible VLESS post-quantum encryption.
//!
//! Adapted from madeye/meow-rs (MIT), itself a wire-compatible port of
//! Xray-core and Mihomo's mlkem768x25519plus client.

mod aead;
mod client;
mod factory;
mod raw_blake3;

pub use client::ClientInstance;
pub use factory::parse_client_encryption;

#[cfg(test)]
pub(crate) mod server;

#[cfg(test)]
mod loopback_tests;
