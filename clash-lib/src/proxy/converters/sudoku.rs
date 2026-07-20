use crate::{
    Error,
    config::internal::proxy::OutboundSudoku,
    proxy::{
        HandlerCommonOptions,
        sudoku::{Handler, HandlerOptions, SudokuOutboundConfig},
    },
};

impl TryFrom<OutboundSudoku> for Handler {
    type Error = Error;

    fn try_from(config: OutboundSudoku) -> Result<Self, Self::Error> {
        let mut enabled = config.http_mask.unwrap_or(true);
        let mut mode = config.http_mask_mode.unwrap_or_else(|| "legacy".to_owned());
        let mut tls = config.http_mask_tls;
        let mut host = config.http_mask_host.unwrap_or_default();
        let mut path_root = config.path_root.unwrap_or_default();
        let mut multiplex = config
            .http_mask_multiplex
            .unwrap_or_else(|| "off".to_owned());

        if let Some(nested) = config.httpmask {
            enabled = !nested.disable;
            if let Some(value) = nested.mode.filter(|value| !value.is_empty()) {
                mode = value;
            }
            tls = nested.tls;
            host = nested.host.unwrap_or_default();
            if let Some(value) = nested.path_root.filter(|value| !value.is_empty()) {
                path_root = value;
            }
            multiplex = nested
                .multiplex
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "off".to_owned());
        }

        let protocol = SudokuOutboundConfig::new(
            config.common_opts.server,
            config.common_opts.port,
            config.key,
            config.aead_method.unwrap_or_default(),
            config.table_type.unwrap_or_default(),
            config.custom_table,
            config.custom_tables,
            config.padding_min,
            config.padding_max,
            config.enable_pure_downlink,
            enabled,
            mode,
            tls,
            host,
            path_root,
            multiplex,
        )
        .map_err(|error| Error::InvalidConfig(error.to_string()))?;

        Handler::new(HandlerOptions {
            name: config.common_opts.name,
            common_opts: HandlerCommonOptions {
                connector: config.common_opts.connect_via,
                ..Default::default()
            },
            config: protocol,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::internal::proxy::OutboundProxyProtocol;

    fn parse(yaml: &str) -> OutboundSudoku {
        match serde_yaml::from_str::<OutboundProxyProtocol>(yaml).unwrap() {
            OutboundProxyProtocol::Sudoku(config) => config,
            _ => panic!("expected sudoku"),
        }
    }

    #[test]
    fn parses_flat_mihomo_options() {
        let handler: Handler = parse(
            "name: sudoku\ntype: sudoku\nserver: example.com\nport: 443\nkey: \
             secret\naead-method: aes-128-gcm\npadding-min: 5\npadding-max: \
             40\ntable-type: up_ascii_down_entropy\nenable-pure-downlink: \
             false\nhttp-mask: true\nhttp-mask-mode: stream\nhttp-mask-tls: \
             true\nhttp-mask-host: cdn.example.com\npath-root: \
             tunnel\nhttp-mask-multiplex: auto\ncustom-tables: [xpxvvpvv, \
             vxpvxvvp]\n",
        )
        .try_into()
        .unwrap();
        assert_eq!(handler.opts.config.custom_patterns.len(), 2);
        assert_eq!(handler.opts.config.padding_min, 5);
        assert_eq!(handler.opts.config.padding_max, 40);
        assert!(!handler.opts.config.pure_downlink);
        assert!(handler.opts.config.http_mask_tls);
    }

    #[test]
    fn nested_httpmask_overrides_flat_options() {
        let handler: Handler = parse(
            "name: sudoku\ntype: sudoku\nserver: example.com\nport: 443\nkey: \
             secret\nhttp-mask: false\nhttp-mask-mode: poll\nhttpmask:\n  disable: \
             false\n  mode: ws\n  tls: true\n  host: edge.example.com\n  \
             path-root: nested\n  multiplex: on\n",
        )
        .try_into()
        .unwrap();
        assert_eq!(
            handler.opts.config.http_mask_mode,
            crate::proxy::sudoku::HttpMaskMode::WebSocket
        );
        assert!(handler.opts.config.session_mux);
        assert_eq!(handler.opts.config.http_mask_path_root, "nested");
    }

    #[test]
    fn rejects_invalid_padding_and_path_root() {
        assert!(
            Handler::try_from(parse(
                "name: bad\ntype: sudoku\nserver: example.com\nport: 443\nkey: \
                 secret\npadding-min: 101\n",
            ))
            .is_err()
        );
        assert!(
            Handler::try_from(parse(
                "name: bad\ntype: sudoku\nserver: example.com\nport: 443\nkey: \
                 secret\npath-root: a/b\n",
            ))
            .is_err()
        );
    }
}
