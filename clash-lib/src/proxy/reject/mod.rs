use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
    },
    config::internal::proxy::PROXY_REJECT,
    proxy::OutboundHandler,
    session::Session,
};
use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use serde::Serialize;
use std::{collections::HashMap, io};

use super::{
    ConnectorType, DialWithConnector, OutboundType, PlainProxyAPIResponse,
    utils::RemoteConnector,
};

#[derive(Debug, thiserror::Error)]
#[error("REJECT")]
struct RejectError;

fn rejection<T>() -> io::Result<T> {
    Err(io::Error::other(RejectError))
}

pub(crate) fn is_reject_error(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.downcast_ref::<RejectError>().is_some())
}

#[derive(Serialize)]
pub struct Handler {
    pub name: String,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reject").field("name", &self.name).finish()
    }
}

impl Handler {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
        }
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        PROXY_REJECT
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Reject
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        rejection()
    }

    async fn connect_datagram(
        &self,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        rejection()
    }

    async fn connect_stream_with_connector(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
        _connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        rejection()
    }

    async fn connect_datagram_with_connector(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
        _connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        rejection()
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        HashMap::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_structured_reject_errors() {
        let error = rejection::<()>().unwrap_err();
        assert!(is_reject_error(&error));
        assert_eq!(error.to_string(), PROXY_REJECT);
        assert!(!is_reject_error(&io::Error::other(PROXY_REJECT)));
    }
}
