use clash_lib::{
    Config, Options, ScaffoldInstance, TokioRuntime, start_scaffold_instance,
};
use std::{
    backtrace::Backtrace,
    ffi::{CStr, CString},
    os::raw::{c_char, c_int, c_void},
    path::PathBuf,
    sync::{LazyLock, Mutex},
    thread::JoinHandle,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

struct RunningInstance {
    core: ScaffoldInstance,
    event_handle: JoinHandle<()>,
    event_token: CancellationToken,
}

type EventCallback = unsafe extern "C" fn(*const c_char);

static RUNNING_INSTANCE: LazyLock<Mutex<Option<RunningInstance>>> =
    LazyLock::new(|| Mutex::new(None));
static EVENT_CALLBACK: LazyLock<Mutex<Option<EventCallback>>> =
    LazyLock::new(|| Mutex::new(None));
static PANIC_REPORT_PATH: LazyLock<Mutex<Option<PathBuf>>> =
    LazyLock::new(|| Mutex::new(None));
static PANIC_REPORTER: std::sync::Once = std::sync::Once::new();

fn install_panic_reporter(cwd: &str) {
    *PANIC_REPORT_PATH.lock().unwrap() =
        Some(PathBuf::from(cwd).join("clash-rs-panic.log"));
    PANIC_REPORTER.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let thread = std::thread::current();
            let location = info
                .location()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_owned());
            let report = format!(
                "thread={}; location={location}; panic={info}; backtrace={}",
                thread.name().unwrap_or("unnamed"),
                Backtrace::force_capture(),
            );
            if let Some(path) = PANIC_REPORT_PATH.lock().unwrap().as_ref() {
                let _ = std::fs::write(path, report);
            }
            default_hook(info);
        }));
    });
}

/// Register the process-wide Android VM and application context used by
/// platform-aware dependencies such as the system DNS resolver.
///
/// # Safety
/// Both pointers must stay valid for the lifetime of the process, and this
/// function must be called exactly once.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clash_initialize_android_context(
    java_vm: *mut c_void,
    context: *mut c_void,
) {
    unsafe {
        clash_lib::initialize_android_context(java_vm, context);
    }
}

fn stop_running_instance() -> bool {
    let Some(instance) = RUNNING_INSTANCE.lock().unwrap().take() else {
        return false;
    };
    instance.event_token.cancel();
    let _ = instance.core.shutdown();
    let _ = instance.event_handle.join();
    true
}

fn start_event_forwarder(token: CancellationToken) -> JoinHandle<()> {
    let mut receiver = clash_lib::app::events::subscribe_app();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build event forwarding runtime");
        runtime.block_on(async move {
            loop {
                let event = tokio::select! {
                    _ = token.cancelled() => break,
                    event = receiver.recv() => event,
                };
                let event = match event {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };
                let Some(callback) = *EVENT_CALLBACK.lock().unwrap() else {
                    continue;
                };
                if let Ok(event) = CString::new(event) {
                    unsafe { callback(event.as_ptr()) };
                }
            }
        });
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn clash_set_event_callback(callback: Option<EventCallback>) {
    *EVENT_CALLBACK.lock().unwrap() = callback;
}

/// Register FlClash's Android `VpnService` flow-to-package callback.
///
/// # Safety
/// The context and callbacks must remain valid until
/// `clash_clear_android_process_resolver` is called.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clash_set_android_process_resolver(
    context: *mut c_void,
    api_level: c_int,
    resolver: Option<clash_lib::process_resolver::AndroidProcessResolver>,
    free: Option<clash_lib::process_resolver::AndroidStringFree>,
    protect: Option<clash_lib::process_resolver::AndroidSocketProtector>,
) {
    unsafe {
        clash_lib::process_resolver::set_android_resolver(
            context, api_level, resolver, free, protect,
        );
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn clash_clear_android_process_resolver() {
    clash_lib::process_resolver::clear_android_resolver();
}

/// Attach an application-owned TUN descriptor to the running clash instance.
///
/// Unlike a config reload, this replaces only the TUN runner and keeps DNS,
/// providers, outbounds, routing state, and the controller alive.
///
/// # Safety
/// `addresses` and `dns` must point to valid NUL-terminated UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clash_attach_tun(
    fd: c_int,
    addresses: *const c_char,
    dns: *const c_char,
) -> c_int {
    if addresses.is_null() || dns.is_null() {
        return 0;
    }
    let Ok(addresses) = unsafe { CStr::from_ptr(addresses) }.to_str() else {
        return 0;
    };
    let Ok(dns) = unsafe { CStr::from_ptr(dns) }.to_str() else {
        return 0;
    };
    match clash_lib::attach_external_tun(fd, addresses, dns) {
        Ok(()) => 1,
        Err(error) => {
            eprintln!("failed to attach external TUN: {error}");
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn clash_detach_tun() -> c_int {
    match clash_lib::detach_external_tun() {
        Ok(()) => 1,
        Err(error) => {
            eprintln!("failed to detach external TUN: {error}");
            0
        }
    }
}

/// Execute a controller request in the running core without opening a local
/// TCP connection. The returned JSON contains `status`, `body`, and `error`.
///
/// # Safety
/// `method` and `path` must be valid NUL-terminated UTF-8 strings. `body` may
/// be null when the request has no payload.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clash_controller_request(
    method: *const c_char,
    path: *const c_char,
    body: *const c_char,
    timeout_ms: u64,
) -> *mut c_char {
    let method = unsafe { CStr::from_ptr(method) }.to_string_lossy();
    let path = unsafe { CStr::from_ptr(path) }.to_string_lossy();
    let body = if body.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(body) }.to_string_lossy())
    };
    let result = match clash_lib::controller_request(
        &method,
        &path,
        body.as_deref(),
        Duration::from_millis(timeout_ms),
    ) {
        Ok(response) => serde_json::json!({
            "status": response.status,
            "body": response.body,
            "error": "",
        }),
        Err(error) => serde_json::json!({
            "status": 0,
            "body": "",
            "error": error.to_string(),
        }),
    };
    CString::new(result.to_string()).unwrap().into_raw()
}

/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clash_start(
    config: *const c_char,
    log: *const c_char,
    cwd: *const c_char,
    multithread: c_int,
) -> *mut c_char {
    unsafe {
        let config_str = CStr::from_ptr(config)
            .to_str()
            .unwrap_or_default()
            .to_string();
        let log_str = CStr::from_ptr(log).to_str().unwrap_or_default().to_string();
        let cwd_str = CStr::from_ptr(cwd).to_str().unwrap_or_default().to_string();
        install_panic_reporter(&cwd_str);

        let rt = if multithread != 0 {
            Some(TokioRuntime::MultiThread)
        } else {
            Some(TokioRuntime::SingleThread)
        };

        let options = Options {
            config: Config::Str(config_str),
            cwd: Some(cwd_str),
            rt,
            log_file: Some(log_str),
            config_path: None,
        };

        stop_running_instance();
        let event_token = CancellationToken::new();
        let event_handle = start_event_forwarder(event_token.clone());
        match start_scaffold_instance(options) {
            Ok(core) => {
                *RUNNING_INSTANCE.lock().unwrap() = Some(RunningInstance {
                    core,
                    event_handle,
                    event_token,
                });
                CString::new("").unwrap().into_raw()
            }
            Err(e) => {
                event_token.cancel();
                let _ = event_handle.join();
                CString::new(format!("Error: {e}")).unwrap().into_raw()
            }
        }
    }
}

/// Validate a configuration without starting the core.
///
/// Returns an empty string on success and an error message otherwise.
///
/// # Safety
/// `config` and `cwd` must point to valid NUL-terminated UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clash_validate(
    config: *const c_char,
    cwd: *const c_char,
) -> *mut c_char {
    unsafe {
        let config_str = CStr::from_ptr(config)
            .to_str()
            .unwrap_or_default()
            .to_string();
        let cwd_str = CStr::from_ptr(cwd).to_str().unwrap_or_default().to_string();

        let options = Options {
            config: Config::Str(config_str),
            cwd: Some(cwd_str),
            rt: Some(TokioRuntime::SingleThread),
            log_file: None,
            config_path: None,
        };

        match options.config.try_parse() {
            Ok(_) => CString::new("").unwrap().into_raw(),
            Err(error) => CString::new(error.to_string())
                .unwrap_or_else(|_| CString::new("invalid config").unwrap())
                .into_raw(),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn clash_shutdown() -> c_int {
    if stop_running_instance() {
        1 // Success
    } else {
        0 // Failure
    }
}

/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unused_must_use)]
pub unsafe extern "C" fn clash_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        CString::from_raw(s);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        clash_controller_request, clash_free_string, clash_shutdown, clash_start,
        clash_validate,
    };
    use std::ffi::{CStr, CString};

    #[test]
    fn start_returns_in_background_and_replaces_a_running_instance_cleanly() {
        let cwd = std::env::temp_dir()
            .join(format!("clash-ffi-background-start-{}", std::process::id()));
        std::fs::create_dir_all(&cwd).unwrap();
        let config = CString::new(
            r#"
mixed-port: 0
dns:
  enable: false
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        let log = CString::new("").unwrap();
        let cwd = CString::new(cwd.to_string_lossy().as_bytes()).unwrap();
        let started = std::time::Instant::now();

        let result =
            unsafe { clash_start(config.as_ptr(), log.as_ptr(), cwd.as_ptr(), 1) };
        let message = unsafe { CStr::from_ptr(result) }.to_string_lossy();

        assert!(message.is_empty(), "{message}");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        unsafe { clash_free_string(result) };

        let method = CString::new("GET").unwrap();
        let path = CString::new("/configs").unwrap();
        let response_ptr = unsafe {
            clash_controller_request(
                method.as_ptr(),
                path.as_ptr(),
                std::ptr::null(),
                2_000,
            )
        };
        let response: serde_json::Value = serde_json::from_str(
            unsafe { CStr::from_ptr(response_ptr) }.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(response["status"], 200);
        assert!(response["error"].as_str().unwrap().is_empty());
        unsafe { clash_free_string(response_ptr) };

        let restarted = std::time::Instant::now();
        let replacement =
            unsafe { clash_start(config.as_ptr(), log.as_ptr(), cwd.as_ptr(), 1) };
        let replacement_message =
            unsafe { CStr::from_ptr(replacement) }.to_string_lossy();
        assert!(replacement_message.is_empty(), "{replacement_message}");
        assert!(restarted.elapsed() < std::time::Duration::from_secs(2));
        unsafe { clash_free_string(replacement) };

        assert_eq!(clash_shutdown(), 1);
    }

    #[test]
    fn validates_flclash_mihomo_compatibility_profile() {
        let config = CString::new(
            r#"
mixed-port: 7890
allow-lan: false
mode: rule
log-level: warn
ipv6: false
unified-delay: true
tcp-concurrent: true
find-process-mode: strict
external-controller: 127.0.0.1:9090
geo-auto-update: true
geo-update-interval: 24
geox-url:
  mmdb: https://example.com/GEOIP.metadb
  asn: https://example.com/ASN.mmdb
  geoip: https://example.com/GEOIP.dat
  geosite: https://example.com/GEOSITE.dat
external-controller-cors:
  allow-origins:
    - '*'
  allow-private-network: true
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 223.5.5.5
  nameserver:
    - https://dns.alidns.com/dns-query
  nameserver-policy:
    geosite:cn:
      - https://dns.alidns.com/dns-query
      - https://doh.pub/dns-query
tun:
  enable: false
  device: utun1989
  stack: mixed
  auto-route: true
  auto-detect-interface: true
  route-address:
    - 0.0.0.0/1
sniffer:
  enable: true
  override-destination: true
  force-dns-mapping: true
  parse-pure-ip: true
  force-domain:
    - +.example.com
  skip-domain:
    - Mijia Cloud
  skip-src-address:
    - 192.168.0.0/16
  skip-dst-address:
    - 10.0.0.1
  sniff:
    TLS:
      ports:
        - 443
        - 8443-9443
    HTTP:
      ports:
        - 80
        - 8080-8880
      override-destination: false
    QUIC:
      ports:
        - 443
proxies:
  - name: compat-ss-uot-v2
    type: ss
    server: example.com
    port: 443
    cipher: aes-128-gcm
    password: password
    udp: true
    udp-over-tcp: true
    udp-over-tcp-version: 2
  - name: compat-ss-v2ray-mux
    type: ss
    server: example.com
    port: 443
    cipher: chacha20-ietf-poly1305
    password: password
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      host: cdn.example.com
      path: /ss
      mux: true
      tls: true
      ech-opts:
        enable: true
        config: AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA
  - name: compat-ss-gost-smux
    type: ss
    server: example.com
    port: 443
    cipher: chacha20-ietf-poly1305
    password: password
    plugin: gost-plugin
    plugin-opts:
      mode: websocket
      host: cdn.example.com
      path: /gost
      mux: true
  - name: compat-ss-shadowtls-v2
    type: ss
    server: example.com
    port: 443
    cipher: chacha20-ietf-poly1305
    password: password
    client-fingerprint: chrome
    plugin: shadow-tls
    plugin-opts:
      host: www.example.com
      password: shadow-password
      version: 2
      alpn: [h2, http/1.1]
  - name: compat-anytls-pool
    type: anytls
    server: example.com
    port: 443
    password: password
    udp: true
    idle-session-check-interval: 15
    idle-session-timeout: 60
    min-idle-session: 2
    client-fingerprint: chrome
    ech-opts:
      enable: true
      config: AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA
  - name: compat-vless
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls: true
    client-fingerprint: firefox
    network: ws
    ws-opts:
      path: /proxy
  - name: compat-vless-packetaddr
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    udp: true
    network: tcp
    packet-encoding: packetaddr
  - name: compat-vless-xudp
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    udp: true
    packet-encoding: xudp
  - name: compat-vless-xhttp-stream-one
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      mode: stream-one
      host: cdn.example.com
      path: /xhttp
      headers:
        X-Compat-Test: flclash
  - name: compat-vless-xhttp-packet-up
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      mode: packet-up
      host: cdn.example.com
      path: /packet
      x-padding-bytes: 128-256
      session-placement: query
      session-key: sid
      seq-placement: header
      seq-key: X-Packet-Seq
      uplink-data-placement: header
      uplink-data-key: X-Packet-Data
      uplink-chunk-size: 256-512
      sc-max-each-post-bytes: 32768
      sc-min-posts-interval-ms: 10-30
      reuse-settings:
        max-concurrency: 8-16
        max-connections: 1-2
        c-max-reuse-times: 100
        h-max-request-times: 1000
        h-max-reusable-secs: 300
        h-keep-alive-period: 45
  - name: compat-vless-xhttp-stream-up
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      mode: stream-up
      host: cdn.example.com
      path: /stream
      x-padding-obfs-mode: true
      x-padding-bytes: 100-200
      x-padding-placement: queryInHeader
      x-padding-key: padding
      x-padding-header: Referer
      x-padding-method: tokenish
      session-placement: cookie
      session-key: session_id
      download-settings:
        server: download-origin.example.com
        port: 8443
        tls: true
        alpn: [h2]
        servername: download-tls.example.com
        skip-cert-verify: true
        client-fingerprint: chrome
        host: download.example.com
        path: /download
        headers:
          X-Download-Test: flclash
        reuse-settings:
          max-concurrency: 4
          max-connections: 1
  - name: compat-vless-xhttp-http1
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls: true
    alpn: [http/1.1]
    network: xhttp
    xhttp-opts:
      mode: stream-one
      host: cdn.example.com
      path: /http1
  - name: compat-vless-xhttp-http1-packet
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls: true
    alpn: [http/1.1]
    network: xhttp
    xhttp-opts:
      mode: packet-up
      host: cdn.example.com
      path: /http1-packet
      reuse-settings:
        max-concurrency: 8
        max-connections: 2
        h-max-request-times: 100
  - name: compat-vless-xhttp-http3-packet
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls: true
    alpn: [h3]
    network: xhttp
    xhttp-opts:
      mode: packet-up
      host: cdn.example.com
      path: /http3-packet
      download-settings:
        server: download-h3.example.com
        port: 8443
        tls: true
        alpn: [h3]
        servername: download-h3-tls.example.com
        skip-cert-verify: true
        host: download-h3-cdn.example.com
        path: /http3-download
  - name: compat-vless-xhttp-h2-h3-split
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      mode: stream-up
      host: cdn.example.com
      path: /h2-upload
      download-settings:
        server: download-h3.example.com
        port: 8443
        tls: true
        alpn: [h3]
        servername: download-h3.example.com
        skip-cert-verify: true
        host: download.example.com
        path: /h3-download
  - name: compat-vless-xhttp-h3-http1-split
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls: true
    alpn: [h3]
    network: xhttp
    xhttp-opts:
      mode: packet-up
      host: cdn.example.com
      path: /h3-upload
      download-settings:
        server: download-http1.example.com
        port: 8443
        tls: true
        alpn: [http/1.1]
        servername: download-http1.example.com
        skip-cert-verify: true
        host: download.example.com
        path: /http1-download
  - name: compat-vmess-http
    type: vmess
    server: example.com
    port: 80
    uuid: 00000000-0000-0000-0000-000000000000
    alterId: 0
    cipher: auto
    network: http
    http-opts:
      method: POST
      path: [/tunnel]
      headers:
        Host: [front.example.com]
  - name: compat-vmess-xudp
    type: vmess
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    alterId: 0
    cipher: aes-128-gcm
    tls: true
    client-fingerprint: safari
    udp: true
    packet-encoding: xudp
    global-padding: true
    authenticated-length: true
  - name: compat-vmess-cfb
    type: vmess
    server: example.com
    port: 80
    uuid: 00000000-0000-0000-0000-000000000000
    alterId: 16
    cipher: aes-128-cfb
  - name: compat-trojan-ss
    type: trojan
    server: example.com
    port: 443
    password: trojan-password
    network: tcp
    skip-cert-verify: true
    client-fingerprint: ios
    ss-opts:
      enabled: true
      method: aes-128-gcm
      password: inner-password
  - name: compat-hysteria
    type: hysteria
    server: example.com
    port: 443
    auth-str: password
    up: 50 Mbps
    down: 100 Mbps
    skip-cert-verify: true
    ech-opts:
      enable: true
      config: AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA
  - name: compat-hysteria2
    type: hysteria2
    server: example.com
    port: 443
    password: password
    skip-cert-verify: true
    ech-opts:
      enable: true
      config: AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA
  - name: compat-http
    type: http
    server: example.com
    port: 443
    username: user
    password: password
    tls: true
    skip-cert-verify: true
    headers:
      X-Compat-Test: flclash
  - name: compat-tuic
    type: tuic
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    password: password
    skip-cert-verify: true
    ech-opts:
      enable: true
      config: AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA
    udp-relay-mode: native
    congestion-controller: bbr
  - name: compat-dns
    type: dns
  - name: compat-gost-relay
    type: gost-relay
    server: example.com
    port: 443
    udp: true
    tls: true
    mux: true
    username: user
    password: password
    skip-cert-verify: true
    client-fingerprint: edge
  - name: compat-snell
    type: snell
    server: example.com
    port: 443
    psk: password
    version: 4
    udp: true
    reuse: true
    obfs-opts:
      mode: tls
      host: bing.com
  - name: compat-ssr-origin
    type: ssr
    server: example.com
    port: 8388
    cipher: aes-128-cfb
    password: password
    protocol: origin
    obfs: plain
    udp: true
  - name: compat-ssr-auth-sha1-v4
    type: ssr
    server: example.com
    port: 8388
    cipher: aes-128-cfb
    password: password
    protocol: auth_sha1_v4
    obfs: plain
    udp: true
  - name: compat-ssr-auth-aes128-md5
    type: ssr
    server: example.com
    port: 8388
    cipher: aes-128-cfb
    password: password
    protocol: auth_aes128_md5
    protocol-param: '1234:per-user-password'
    obfs: plain
    udp: true
  - name: compat-ssr-auth-aes128-sha1
    type: ssr
    server: example.com
    port: 8388
    cipher: aes-128-cfb
    password: password
    protocol: auth_aes128_sha1
    protocol-param: '4321:per-user-password'
    obfs: plain
    udp: true
  - name: compat-ssr-http
    type: ssr
    server: example.com
    port: 80
    cipher: aes-128-cfb
    password: password
    protocol: origin
    obfs: http_simple
    obfs-param: cdn.example.com
    udp: true
  - name: compat-ssr-post
    type: ssr
    server: example.com
    port: 80
    cipher: aes-128-cfb
    password: password
    protocol: origin
    obfs: http_post
  - name: compat-ssr-random-head
    type: ssr
    server: example.com
    port: 8388
    cipher: aes-128-cfb
    password: password
    protocol: origin
    obfs: random_head
  - name: compat-ssr-tls12-ticket
    type: ssr
    server: example.com
    port: 443
    cipher: aes-128-cfb
    password: password
    protocol: auth_aes128_sha1
    protocol-param: '4321:per-user-password'
    obfs: tls1.2_ticket_auth
    obfs-param: cdn.example.com
  - name: compat-ssr-auth-chain-a
    type: ssr
    server: example.com
    port: 8388
    cipher: aes-128-cfb
    password: password
    protocol: auth_chain_a
    protocol-param: '1234:per-user-password'
    obfs: plain
    udp: true
  - name: compat-ssr-auth-chain-b
    type: ssr
    server: example.com
    port: 443
    cipher: aes-128-cfb
    password: password
    protocol: auth_chain_b
    protocol-param: '4321:per-user-password'
    obfs: tls1.2_ticket_fastauth
    obfs-param: cdn.example.com
    udp: true
  - name: compat-mieru
    type: mieru
    server: example.com
    port: 443
    transport: TCP
    udp: true
    username: user
    password: password
    multiplexing: MULTIPLEXING_HIGH
    handshake-mode: HANDSHAKE_NO_WAIT
    traffic-pattern: GgQIARAK
  - name: compat-trusttunnel
    type: trusttunnel
    server: example.com
    port: 443
    username: user
    password: password
    alpn:
      - h2
    udp: true
    skip-cert-verify: true
    client-fingerprint: android
  - name: compat-trusttunnel-h3
    type: trusttunnel
    server: example.com
    port: 443
    username: user
    password: password
    alpn:
      - h3
    udp: true
    quic: true
    health-check: true
    skip-cert-verify: true
    client-fingerprint: android
    congestion-controller: bbr
    cwnd: 32
    bbr-profile: mobile
    max-connections: 4
    min-streams: 2
  - name: compat-masque-h2
    type: masque
    server: 162.159.198.1
    port: 443
    private-key: MHcCAQEEILI1eOtnbEIh89Fj4yNDuFR6UjayCKI3NdLl3DhetimWoAoGCCqGSM49AwEHoUQDQgAEgyXrE8v+hHsHy3ewSb3WcRjYgCrM9T9hiE0Uv6k2DZ1+4kefrDT9v1Q/8wdRigTf6t6gGNUV8W+IUMdrfUt+9g==
    public-key: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==
    ip: 172.16.0.2/32
    network: h2
    udp: true
    skip-cert-verify: true
  - name: compat-masque-h3
    type: masque
    server: 162.159.198.1
    port: 443
    private-key: MHcCAQEEILI1eOtnbEIh89Fj4yNDuFR6UjayCKI3NdLl3DhetimWoAoGCCqGSM49AwEHoUQDQgAEgyXrE8v+hHsHy3ewSb3WcRjYgCrM9T9hiE0Uv6k2DZ1+4kefrDT9v1Q/8wdRigTf6t6gGNUV8W+IUMdrfUt+9g==
    public-key: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==
    ip: 172.16.0.2/32
    network: h3
    udp: true
    skip-cert-verify: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - compat-ss-uot-v2
      - compat-ss-v2ray-mux
      - compat-ss-gost-smux
      - compat-ss-shadowtls-v2
      - compat-anytls-pool
      - compat-vless
      - compat-vless-packetaddr
      - compat-vless-xudp
      - compat-vless-xhttp-stream-one
      - compat-vless-xhttp-packet-up
      - compat-vless-xhttp-stream-up
      - compat-vless-xhttp-http1
      - compat-vless-xhttp-http1-packet
      - compat-vless-xhttp-http3-packet
      - compat-vless-xhttp-h2-h3-split
      - compat-vless-xhttp-h3-http1-split
      - compat-vmess-http
      - compat-vmess-xudp
      - compat-vmess-cfb
      - compat-trojan-ss
      - compat-hysteria
      - compat-hysteria2
      - compat-http
      - compat-tuic
      - compat-dns
      - compat-gost-relay
      - compat-snell
      - compat-mieru
      - compat-trusttunnel
      - compat-trusttunnel-h3
      - compat-masque-h2
      - compat-masque-h3
      - DIRECT
rules:
  - DOMAIN-SUFFIX,example.com,PROXY
  - DOMAIN-WILDCARD,*.google.com,PROXY
  - IP-ASN,13335,PROXY,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,src
  - GEOIP,CN,DIRECT,src
  - IP-SUFFIX,8.8.8.8/24,PROXY
  - SRC-IP-SUFFIX,192.168.1.201/8,DIRECT
  - SRC-IP-ASN,4134,DIRECT
  - SRC-GEOIP,cn,DIRECT
  - DST-PORT,80/443/1000-2000,PROXY
  - SRC-PORT,7777/8000-8100,DIRECT
  - PROCESS-NAME-WILDCARD,*telegram*,PROXY
  - PROCESS-PATH-WILDCARD,/usr/*/wget,PROXY
  - PROCESS-NAME-REGEX,(?i)Telegram,PROXY
  - PROCESS-PATH-REGEX,.*bin/wget,PROXY
  - IN-TYPE,SOCKS/HTTP,PROXY
  - IN-USER,alice/bob,DIRECT
  - IN-PORT,7890/8000-8100,PROXY
  - IN-NAME,DEFAULT-MIXED/DEFAULT-TUN,PROXY
  - UID,1000/10000-19999,DIRECT
  - DSCP,0/8-16,PROXY
  - SUB-RULE,(OR,((NETWORK,TCP),(NETWORK,UDP))),compat-branch
  - MATCH,PROXY
sub-rules:
  compat-branch:
    - DOMAIN,sub-rule.example,DIRECT
    - MATCH,PROXY
"#,
        )
        .unwrap();
        let cwd = CString::new(".").unwrap();

        let result = unsafe { clash_validate(config.as_ptr(), cwd.as_ptr()) };
        let message = unsafe { CStr::from_ptr(result) }
            .to_str()
            .unwrap()
            .to_string();
        unsafe { clash_free_string(result) };

        assert!(message.is_empty(), "validation failed: {message}");
    }

    #[test]
    fn rejects_unknown_proxy_instead_of_silently_dropping_it() {
        let config = CString::new(
            r#"
mixed-port: 7890
proxies:
  - name: must-not-disappear
    type: imaginary-protocol
    server: example.com
    port: 443
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        let cwd = CString::new(".").unwrap();

        let result = unsafe { clash_validate(config.as_ptr(), cwd.as_ptr()) };
        let message = unsafe { CStr::from_ptr(result) }
            .to_str()
            .unwrap()
            .to_string();
        unsafe { clash_free_string(result) };

        assert!(!message.is_empty(), "unknown proxy unexpectedly validated");
        assert!(
            message.contains("imaginary-protocol"),
            "error should identify the unsupported type: {message}",
        );
    }

    #[test]
    fn rejects_invalid_sniffer_during_validation() {
        let config = CString::new(
            r#"
mixed-port: 7890
sniffer:
  enable: true
  sniff:
    QUIC:
      ports:
        - invalid-port
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        let cwd = CString::new(".").unwrap();

        let result = unsafe { clash_validate(config.as_ptr(), cwd.as_ptr()) };
        let message = unsafe { CStr::from_ptr(result) }
            .to_str()
            .unwrap()
            .to_string();
        unsafe { clash_free_string(result) };

        assert!(
            message.contains("invalid-port"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn sniffs_mihomo_quic_initial_corpus() {
        let packet = hex::decode(concat!(
            "cd0000000108f1fb7bcc78aa5e7203a8f86400421531fe825b19541876db6c55c3",
            "8890cd73149d267a084afee6087304095417a3033df6a81bbb71d8512e7a3e16d",
            "f1e277cae5df3182cb214b8fe982ba3fdffbaa9ffec474547d55945f0fddbeadf",
            "b0b5243890b2fa3da45169e2bd34ec04b2e29382f48d612b28432a559757504d1",
            "58e9e505407a77dd34f4b60b8d3b555ee85aacd6648686802f4de25e7216b19e",
            "54c5f78e8a5963380c742d861306db4c16e4f7fc94957aa50b9578a0b61f1e40",
            "6b2ad5f0cd3cd271c4d99476409797b0c3cb3efec256118912d4b7e4fd79d9cb",
            "9016b6e5eaa4f5e57b637b217755daf8968a4092bed0ed5413f5d04904b3a61e",
            "4064f9211b2629e5b52a89c7b19f37a713e41e27743ea6dfa736dfa1bb0a4b2b",
            "c8c8dc632c6ce963493a20c550e6fdb2475213665e9a85cfc394da9cec0cf41f",
            "0c8abed3fc83be5245b2b5aa5e825d29349f721d30774ef5bf965b540f3d8d98",
            "febe20956b1fc8fa047e10e7d2f921c9c6622389e02322e80621a1cf5264e245",
            "b7276966eb02932584e3f7038bd36aa908766ad3fb98344025dec18670d6db43a",
            "1c5daac00937fce7b7c7d61ff4e6efd01a2bdee0ee183108b926393df4f3d74b",
            "bcbb015f240e7e346b7d01c41111a401225ce3b095ab4623a5836169bf9599ee",
            "ca79d1d2e9b2202b5960a09211e978058d6fc0484eff3e91ce4649a5e3ba15b9",
            "06d334cf66e28d9ff575406e1ae1ac2febafd72870b6f5d58fc5fb949cb1f40f",
            "eb7c1d9ce5e71b",
        ))
        .unwrap();
        assert_eq!(
            clash_lib::app::sniffer::sniff_quic_initial_host(&packet).as_deref(),
            Some("www.google.com"),
        );
    }
}
