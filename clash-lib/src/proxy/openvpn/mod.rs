//! Mihomo-compatible OpenVPN client protocol.
//!
//! The wire implementation follows Mihomo's install-script subset: OpenVPN 2
//! key method 2, optional tls-crypt, UDP/TCP packet transports, AEAD/CBC data
//! channels, replay protection, pushed addresses/routes and comp-lzo framing.

mod client;
mod config;
mod control;
mod data;
mod handler;
mod io;
mod key_method;
mod packet;
mod push;
mod tls_crypt;

pub use config::ClientConfig;
pub use handler::{Handler, HandlerOptions};
