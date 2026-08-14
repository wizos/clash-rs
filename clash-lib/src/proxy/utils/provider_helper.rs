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
    let mut fallback = vec![];
    let mut proxy_names = HashSet::new();
    for provider in providers {
        if touch {
            provider.touch().await;
        }

        let mut proxies_from_provider = provider.proxies().await.to_vec();

        if provider.is_fallback() {
            fallback.append(&mut proxies_from_provider);
            continue;
        }

        proxies_from_provider.retain(|p| proxy_names.insert(p.name().to_owned()));

        proxies.append(&mut proxies_from_provider);
    }
    if proxies.is_empty() {
        proxies.append(&mut fallback);
    }
    if proxies.is_empty() {
        proxies.push(Arc::new(direct::Handler::new(PROXY_COMPATIBLE)));
    }
    proxies
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::{
            dns::MockClashResolver,
            remote_content_manager::{
                ProxyManager, healthcheck::HealthCheck,
                providers::proxy_provider::PlainProvider,
            },
        },
        config::internal::proxy::PROXY_REJECT,
        proxy::reject,
    };

    #[tokio::test]
    async fn empty_group_uses_compatible_fallback() {
        let providers = vec![];
        let proxies = get_proxies_from_providers(&providers, false).await;

        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].name(), PROXY_COMPATIBLE);
    }

    #[tokio::test]
    async fn empty_dynamic_group_uses_its_custom_fallback() {
        let fallback: AnyOutboundHandler =
            Arc::new(reject::Handler::new(PROXY_REJECT));
        let hc = HealthCheck::new(
            vec![fallback.clone()],
            String::new(),
            0,
            true,
            ProxyManager::new(Arc::new(MockClashResolver::new()), None),
        );
        let provider: ArcProxyProvider = Arc::new(
            PlainProvider::new_fallback(
                "group#empty-fallback".to_owned(),
                vec![fallback],
                hc,
            )
            .unwrap(),
        );

        let proxies =
            get_proxies_from_providers(&vec![provider.clone()], false).await;

        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].name(), PROXY_REJECT);

        let ordinary: AnyOutboundHandler = Arc::new(direct::Handler::new(
            crate::config::internal::proxy::PROXY_DIRECT,
        ));
        let hc = HealthCheck::new(
            vec![ordinary.clone()],
            String::new(),
            0,
            true,
            ProxyManager::new(Arc::new(MockClashResolver::new()), None),
        );
        let ordinary_provider: ArcProxyProvider = Arc::new(
            PlainProvider::new("group".to_owned(), vec![ordinary], hc).unwrap(),
        );
        let proxies =
            get_proxies_from_providers(&vec![ordinary_provider, provider], false)
                .await;

        assert_eq!(proxies.len(), 1);
        assert_eq!(
            proxies[0].name(),
            crate::config::internal::proxy::PROXY_DIRECT
        );
    }
}
