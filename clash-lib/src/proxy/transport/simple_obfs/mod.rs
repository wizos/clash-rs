mod http;
mod tls;

#[deprecated(
    since = "0.1.0",
    note = "should be removed since v2ray-plugin is widely used"
)]
pub use http::Client as SimpleObfsHttp;
pub use tls::Client as SimpleObfsTLS;

#[cfg(feature = "shadowsocks")]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SimpleOBFSMode {
    Http,
    Tls,
}

#[cfg(feature = "shadowsocks")]
pub struct SimpleOBFSOption {
    pub mode: SimpleOBFSMode,
    pub host: String,
}
