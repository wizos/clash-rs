use std::net::IpAddr;

use crate::{
    app::net::Interface,
    common::http::DEFAULT_USER_AGENT,
    config::{
        config::{BindAddress, Controller, General},
        def,
    },
};

pub(super) fn convert(c: &def::Config) -> Result<General, crate::Error> {
    let bind_address = if c.bind_address == BindAddress::default() && c.ipv6 {
        BindAddress::dual_stack()
    } else {
        c.bind_address
    };

    // Merge geox-url nested values with flat fields (nested takes precedence)
    let (mmdb_download_url, asn_mmdb_download_url, geosite_download_url) =
        if let Some(ref geox) = c.geox_url {
            (
                geox.mmdb
                    .as_deref()
                    .or(c.mmdb_download_url.as_deref())
                    .map(String::from),
                geox.asn
                    .as_deref()
                    .or(c.asn_mmdb_download_url.as_deref())
                    .map(String::from),
                geox.geosite
                    .as_deref()
                    .or(c.geosite_download_url.as_deref())
                    .map(String::from),
            )
        } else {
            (
                c.mmdb_download_url.clone(),
                c.asn_mmdb_download_url.clone(),
                c.geosite_download_url.clone(),
            )
        };

    // Merge external-controller-cors nested values with flat cors-allow-origins
    let cors_allow_origins = c
        .external_controller_cors
        .as_ref()
        .and_then(|cors| cors.allow_origins.clone())
        .or(c.cors_allow_origins.clone());
    let mmdb = c.mmdb.clone().or_else(|| {
        mmdb_download_url
            .as_ref()
            .map(|_| "Country.mmdb".to_owned())
    });
    let asn_mmdb = c.asn_mmdb.clone().or_else(|| {
        asn_mmdb_download_url
            .as_ref()
            .map(|_| "ASN.mmdb".to_owned())
    });
    let geosite = c.geosite.clone().or_else(|| {
        geosite_download_url
            .as_ref()
            .map(|_| "GEOSITE.dat".to_owned())
    });

    let global_ua = c
        .global_ua
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_USER_AGENT)
        .parse()
        .map_err(|error| {
            crate::Error::InvalidConfig(format!(
                "invalid global-ua HTTP header value: {error}"
            ))
        })?;

    Ok(General {
        authentication: c.authentication.clone(),
        controller: Controller {
            external_controller: c.external_controller.clone(),
            external_ui: c.external_ui.clone(),
            external_ui_download_url: c.external_ui_url.clone(),
            secret: c.secret.clone(),
            cors_allow_origins,
            external_controller_ipc: c.external_controller_ipc.clone(),
        },
        mode: c.mode,
        log_level: c.log_level,
        global_ua,
        ipv6: c.ipv6,
        interface: c.interface.as_ref().map(|iface| {
            if let Ok(addr) = iface.parse::<IpAddr>() {
                Interface::IpAddr(addr)
            } else {
                Interface::Name(iface.to_string())
            }
        }),
        routing_mask: c.routing_mark,
        mmdb,
        mmdb_download_url,
        asn_mmdb,
        asn_mmdb_download_url,
        geosite,
        geosite_download_url,
        bind_address,
        unified_delay: c.unified_delay,
        tcp_concurrent: c.tcp_concurrent,
        find_process_mode: c.find_process_mode,
        sniffer: c.sniffer.clone(),
    })
}
