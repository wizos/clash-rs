use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    net::SocketAddr,
    sync::{
        OnceLock, RwLock,
        atomic::{AtomicU8, Ordering},
    },
};

use crate::{
    config::def::FindProcessMode,
    session::{Network, Session, SocksAddr},
};

#[cfg(any(test, target_os = "android"))]
use std::net::IpAddr;

pub type AndroidProcessResolver = unsafe extern "C" fn(
    context: *mut c_void,
    protocol: c_int,
    source: *const c_char,
    target: *const c_char,
    uid: c_int,
) -> *mut c_char;
pub type AndroidStringFree = unsafe extern "C" fn(value: *mut c_char);
pub type AndroidSocketProtector =
    unsafe extern "C" fn(context: *mut c_void, fd: c_int);

#[derive(Clone, Copy)]
struct Resolver {
    context: usize,
    #[cfg(target_os = "android")]
    api_level: c_int,
    resolve: AndroidProcessResolver,
    free: Option<AndroidStringFree>,
    protect: Option<AndroidSocketProtector>,
}

fn resolver() -> &'static RwLock<Option<Resolver>> {
    static RESOLVER: OnceLock<RwLock<Option<Resolver>>> = OnceLock::new();
    RESOLVER.get_or_init(|| RwLock::new(None))
}

static FIND_PROCESS_MODE: AtomicU8 = AtomicU8::new(0);

pub fn set_find_process_mode(mode: FindProcessMode) {
    FIND_PROCESS_MODE.store(
        match mode {
            FindProcessMode::Strict => 0,
            FindProcessMode::Always => 1,
            FindProcessMode::Off => 2,
        },
        Ordering::Relaxed,
    );
}

pub fn should_resolve_always() -> bool {
    FIND_PROCESS_MODE.load(Ordering::Relaxed) == 1
}

pub fn should_resolve_for_rule() -> bool {
    FIND_PROCESS_MODE.load(Ordering::Relaxed) != 2
}

/// Install the Android `VpnService` process/package resolver supplied by the
/// FlClash JNI adapter.
///
/// # Safety
/// `context` and all callbacks must remain valid until
/// `clear_android_resolver` is called.
pub unsafe fn set_android_resolver(
    context: *mut c_void,
    _api_level: c_int,
    resolve: Option<AndroidProcessResolver>,
    free: Option<AndroidStringFree>,
    protect: Option<AndroidSocketProtector>,
) {
    let value = resolve.map(|resolve| Resolver {
        context: context as usize,
        #[cfg(target_os = "android")]
        api_level: _api_level,
        resolve,
        free,
        protect,
    });
    *resolver().write().expect("process resolver lock poisoned") = value;
}

pub fn clear_android_resolver() {
    *resolver().write().expect("process resolver lock poisoned") = None;
}

pub fn protect_socket(fd: c_int) {
    let resolver = resolver().read().expect("process resolver lock poisoned");
    if let Some(resolver) = resolver.as_ref()
        && let Some(protect) = resolver.protect
    {
        unsafe { protect(resolver.context as *mut c_void, fd) };
    }
}

/// Resolve and attach Android UID/package metadata for a concrete IP flow.
/// The callback result is `uid\npackage`; a plain package string remains
/// accepted for compatibility with older FlClash JNI implementations.
pub fn resolve_session(sess: &mut Session) {
    if !cfg!(target_os = "android")
        || FIND_PROCESS_MODE.load(Ordering::Relaxed) == 2
        || !sess.process.is_empty()
    {
        return;
    }
    let Some(target) = android_lookup_target(sess) else {
        return;
    };
    let source = match CString::new(sess.source.to_string()) {
        Ok(source) => source,
        Err(_) => return,
    };
    let target = match CString::new(target.to_string()) {
        Ok(target) => target,
        Err(_) => return,
    };
    // Keep the read guard until the JNI callback and returned string are done.
    // clear_android_resolver() may release the callback's Java global ref.
    let resolver = resolver().read().expect("process resolver lock poisoned");
    let Some(resolver) = resolver.as_ref() else {
        return;
    };
    let protocol = match sess.network {
        Network::Tcp => 6,
        Network::Udp => 17,
    };
    #[cfg(target_os = "android")]
    let uid_hint = if sess.uid != 0 {
        sess.uid as c_int
    } else if needs_procfs_uid_fallback(resolver.api_level) {
        find_android_uid(sess.network, sess.source.ip(), sess.source.port())
            .map(|uid| uid as c_int)
            .unwrap_or(-1)
    } else {
        -1
    };
    #[cfg(not(target_os = "android"))]
    let uid_hint = sess.uid as c_int;
    let result = unsafe {
        (resolver.resolve)(
            resolver.context as *mut c_void,
            protocol,
            source.as_ptr(),
            target.as_ptr(),
            uid_hint,
        )
    };
    if result.is_null() {
        return;
    }
    let value = unsafe { CStr::from_ptr(result) }
        .to_string_lossy()
        .into_owned();
    if let Some(free) = resolver.free {
        unsafe { free(result) };
    }

    if let Some((uid, package)) = value.split_once('\n') {
        if let Ok(uid) = uid.parse::<u32>() {
            sess.uid = uid;
        }
        sess.process = package.to_string();
    } else {
        sess.process = value;
    }
}

fn android_lookup_target(sess: &Session) -> Option<SocketAddr> {
    if sess.source.ip().is_loopback() && sess.inbound_port != 0 {
        return Some(SocketAddr::new(sess.source.ip(), sess.inbound_port));
    }
    match (&sess.destination, sess.resolved_ip) {
        (SocksAddr::Ip(addr), _) => Some(*addr),
        (SocksAddr::Domain(_, port), Some(ip)) => Some((ip, *port).into()),
        (SocksAddr::Domain(..), None) => None,
    }
}

#[cfg(any(test, target_os = "android"))]
fn needs_procfs_uid_fallback(api_level: c_int) -> bool {
    api_level < 29
}

/// Android < 10 has no `ConnectivityManager.getConnectionOwnerUid`. Mirror
/// Mihomo's procfs fallback by matching the application's local socket port,
/// preferring an exact local IP when the TUN metadata exposes it.
#[cfg(target_os = "android")]
fn find_android_uid(network: Network, ip: IpAddr, port: u16) -> Option<u32> {
    let protocol = match network {
        Network::Tcp => "tcp",
        Network::Udp => "udp",
    };
    let ip = match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    };
    let mut best = None;
    for (path, ipv6) in [
        (format!("/proc/net/{protocol}"), false),
        (format!("/proc/net/{protocol}6"), true),
    ] {
        let expected_ip = match (ip, ipv6) {
            (IpAddr::V4(ip), false) => IpAddr::V4(ip),
            (IpAddr::V4(ip), true) => IpAddr::V6(ip.to_ipv6_mapped()),
            (IpAddr::V6(_), false) => continue,
            (IpAddr::V6(ip), true) => IpAddr::V6(ip),
        };
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Some((uid, exact)) =
            find_uid_in_proc_net(&content, ipv6, expected_ip, port)
        {
            if exact {
                return Some(uid);
            }
            if best.is_none() || best == Some(0) && uid != 0 {
                best = Some(uid);
            }
        }
    }
    best
}

#[cfg(any(test, target_os = "android"))]
fn find_uid_in_proc_net(
    content: &str,
    ipv6: bool,
    expected_ip: IpAddr,
    expected_port: u16,
) -> Option<(u32, bool)> {
    let mut best = None;
    for line in content.lines().skip(1) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 {
            continue;
        }
        let Some((ip, port)) = parse_proc_address(fields[1], ipv6) else {
            continue;
        };
        if port != expected_port {
            continue;
        }
        let (Ok(uid), Ok(inode)) =
            (fields[7].parse::<u32>(), fields[9].parse::<u64>())
        else {
            continue;
        };
        if ip == expected_ip {
            return Some((uid, true));
        }
        if inode != 0 && (best.is_none() || best == Some(0) && uid != 0) {
            best = Some(uid);
        }
    }
    best.map(|uid| (uid, false))
}

#[cfg(any(test, target_os = "android"))]
fn parse_proc_address(value: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (address, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if ipv6 {
        if address.len() != 32 {
            return None;
        }
        let mut octets = [0u8; 16];
        for word in 0..4 {
            let value =
                u32::from_str_radix(&address[word * 8..word * 8 + 8], 16).ok()?;
            octets[word * 4..word * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        Some((IpAddr::V6(octets.into()), port))
    } else {
        if address.len() != 8 {
            return None;
        }
        let value = u32::from_str_radix(address, 16).ok()?;
        Some((IpAddr::V4(value.to_le_bytes().into()), port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn assert_locked_resolve(
        _context: *mut c_void,
        _protocol: c_int,
        _source: *const c_char,
        _target: *const c_char,
        _uid: c_int,
    ) -> *mut c_char {
        assert!(resolver().try_write().is_err());
        std::ptr::null_mut()
    }

    unsafe extern "C" fn assert_locked_protect(_context: *mut c_void, _fd: c_int) {
        assert!(resolver().try_write().is_err());
    }

    #[test]
    fn resolver_is_a_noop_without_callback() {
        clear_android_resolver();
        let mut session = Session::default();
        resolve_session(&mut session);
        assert!(session.process.is_empty());
        assert_eq!(session.uid, 0);
    }

    #[test]
    fn keeps_android_callback_alive_while_it_is_invoked() {
        unsafe {
            set_android_resolver(
                std::ptr::null_mut(),
                36,
                Some(assert_locked_resolve),
                None,
                Some(assert_locked_protect),
            );
        }
        protect_socket(1);
        let mut session = Session {
            source: "172.19.0.1:45678".parse().unwrap(),
            destination: SocksAddr::Ip("1.1.1.1:443".parse().unwrap()),
            ..Default::default()
        };
        resolve_session(&mut session);
        clear_android_resolver();
    }

    #[test]
    fn uses_local_proxy_listener_for_android_process_lookup() {
        let session = Session {
            source: "127.0.0.1:45678".parse().unwrap(),
            destination: SocksAddr::Domain("api.ip.sb".to_string(), 443),
            inbound_port: 7890,
            ..Default::default()
        };

        assert_eq!(
            android_lookup_target(&session),
            Some("127.0.0.1:7890".parse().unwrap()),
        );
    }

    #[test]
    fn uses_procfs_uid_fallback_only_before_android_10() {
        assert!(needs_procfs_uid_fallback(28));
        assert!(!needs_procfs_uid_fallback(29));
    }

    #[test]
    fn parses_android_procfs_socket_owner() {
        let proc_net = "  sl  local_address rem_address st tx_queue rx_queue tr \
                        tm->when retrnsmt uid timeout inode\n0: 020013AC:CB20 \
                        08080808:01BB 01 00000000:00000000 00:00000000 00000000 \
                        10123 0 424242\n";
        assert_eq!(
            find_uid_in_proc_net(
                proc_net,
                false,
                "172.19.0.2".parse().unwrap(),
                0xcb20,
            ),
            Some((10123, true)),
        );
    }

    #[test]
    fn parses_android_procfs_ipv6_word_endianness() {
        let (address, port) =
            parse_proc_address("0000000000000000FFFF0000020013AC:01BB", true)
                .unwrap();
        assert_eq!(address, "::ffff:172.19.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(port, 443);
    }
}
