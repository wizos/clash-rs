use crate::{
    app::remote_content_manager::providers::proxy_provider::ArcProxyProvider,
    config::internal::proxy::PROXY_COMPATIBLE,
    proxy::{AnyOutboundHandler, direct},
};
use std::{collections::HashSet, sync::Arc};

pub async fn get_proxies_from_providers(
    providers: &Vec<ArcProxyProvider>,
    touch: bool,
) -> Vec<AnyOutboundHandler> {
    let mut proxies = vec![];
    let mut proxy_names = HashSet::new();
    for provider in providers {
        if touch {
            provider.touch().await;
        }

        let mut proxies_from_provider = provider.proxies().await.to_vec();

        proxies_from_provider.retain(|p| proxy_names.insert(p.name().to_owned()));

        proxies.append(&mut proxies_from_provider);
    }
    if proxies.is_empty() {
        proxies.push(Arc::new(direct::Handler::new(PROXY_COMPATIBLE)));
    }
    proxies
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_group_uses_compatible_fallback() {
        let providers = vec![];
        let proxies = get_proxies_from_providers(&providers, false).await;

        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].name(), PROXY_COMPATIBLE);
    }
}
