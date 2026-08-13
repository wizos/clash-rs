use super::DEFAULT_DNS_SERVER_TTL;
use crate::app::dns::{ThreadSafeDNSResolver, helper::build_dns_response_message};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{
        RData, Record, RecordType,
        rdata::{
            A, HTTPS,
            svcb::{Mandatory, SVCB, SvcParamKey, SvcParamValue},
        },
    },
};
use tracing::debug;

pub async fn exchange_with_resolver<'a>(
    resolver: &'a ThreadSafeDNSResolver,
    req: &'a Message,
    enhanced: bool,
) -> Result<Message, watfaq_dns::DNSError> {
    let query = req
        .queries
        .first()
        .ok_or(watfaq_dns::DNSError::InvalidOpQuery(
            "malformed query message".to_string(),
        ))?;
    let query_type = query.query_type();
    let host = query.name().to_ascii().trim_end_matches('.').to_owned();
    let fake_ip_enabled = resolver.fake_ip_enabled();

    if query_type != RecordType::A || !fake_ip_enabled {
        return match resolver.exchange(req).await {
            Ok(mut response) => {
                if enhanced
                    && fake_ip_enabled
                    && matches!(query_type, RecordType::HTTPS | RecordType::SVCB)
                    && resolver.fake_ip_active_for(&host).await
                {
                    for answer in &mut response.answers {
                        *answer = strip_svc_ip_hints(answer);
                    }
                }
                Ok(response)
            }
            Err(e) => {
                debug!("dns resolve error: {}", e);
                Err(watfaq_dns::DNSError::QueryFailed(e.to_string()))
            }
        };
    }

    let name = query.name().clone();

    let mut res = build_dns_response_message(req, false, false);

    match resolver.resolve_v4(&host, enhanced).await {
        Ok(resp) => match resp {
            Some(ip) => {
                let rdata = RData::A(A(ip));

                let records =
                    vec![Record::from_rdata(name, DEFAULT_DNS_SERVER_TTL, rdata)];

                res.metadata.response_code = ResponseCode::NoError;
                res.add_answers(records);

                Ok(res)
            }
            None => {
                res.metadata.response_code = ResponseCode::NXDomain;
                Ok(res)
            }
        },
        Err(e) => {
            debug!("dns resolve error: {}", e);
            Err(watfaq_dns::DNSError::QueryFailed(e.to_string()))
        }
    }
}

fn strip_svc_ip_hints(record: &Record) -> Record {
    fn is_hint(key: SvcParamKey) -> bool {
        matches!(key, SvcParamKey::Ipv4Hint | SvcParamKey::Ipv6Hint)
    }

    fn strip(svcb: &SVCB) -> SVCB {
        let mut params = Vec::with_capacity(svcb.svc_params.len());
        for (key, value) in &svcb.svc_params {
            if is_hint(*key) {
                continue;
            }
            if let (
                SvcParamKey::Mandatory,
                SvcParamValue::Mandatory(Mandatory(keys)),
            ) = (key, value)
            {
                let keys = keys
                    .iter()
                    .copied()
                    .filter(|key| !is_hint(*key))
                    .collect::<Vec<_>>();
                if !keys.is_empty() {
                    params.push((
                        SvcParamKey::Mandatory,
                        SvcParamValue::Mandatory(Mandatory(keys)),
                    ));
                }
                continue;
            }
            params.push((*key, value.clone()));
        }
        SVCB::new(svcb.svc_priority, svcb.target_name.clone(), params)
    }

    let mut record = record.clone();
    record.data = match &record.data {
        RData::HTTPS(https) => RData::HTTPS(HTTPS(strip(&https.0))),
        RData::SVCB(svcb) => RData::SVCB(strip(svcb)),
        _ => return record,
    };
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::{MockClashResolver, ThreadSafeDNSResolver};
    use hickory_proto::{
        op::{MessageType, OpCode, Query},
        rr::{
            Name,
            rdata::{
                AAAA,
                svcb::{Alpn, EchConfigList, IpHint},
            },
        },
    };
    use std::{net::Ipv4Addr, sync::Arc};

    fn request(record_type: RecordType) -> Message {
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            record_type,
        ));
        message
    }

    fn response(req: &Message, data: RData) -> Message {
        let mut response =
            Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
        response.add_queries(req.queries.clone());
        response.add_answer(Record::from_rdata(
            req.queries[0].name().clone(),
            300,
            data,
        ));
        response
    }

    fn svc_data(record_type: RecordType) -> RData {
        let params = vec![
            (
                SvcParamKey::Mandatory,
                SvcParamValue::Mandatory(Mandatory(vec![
                    SvcParamKey::Alpn,
                    SvcParamKey::Ipv4Hint,
                    SvcParamKey::Ipv6Hint,
                ])),
            ),
            (
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(vec!["h3".to_owned(), "h2".to_owned()])),
            ),
            (SvcParamKey::Port, SvcParamValue::Port(8443)),
            (
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A(Ipv4Addr::new(
                    203, 0, 113, 7,
                ))])),
            ),
            (
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(vec![0xab, 0xcd])),
            ),
            (
                SvcParamKey::Ipv6Hint,
                SvcParamValue::Ipv6Hint(IpHint(vec![AAAA(
                    "2001:db8::7".parse().unwrap(),
                )])),
            ),
        ];
        let svcb = SVCB::new(1, Name::root(), params);
        match record_type {
            RecordType::HTTPS => RData::HTTPS(HTTPS(svcb)),
            RecordType::SVCB => RData::SVCB(svcb),
            _ => unreachable!(),
        }
    }

    fn exchanging_resolver(
        fake_ip: bool,
        fake_ip_active: Option<bool>,
        upstream: Message,
    ) -> ThreadSafeDNSResolver {
        let mut resolver = MockClashResolver::new();
        resolver.expect_fake_ip_enabled().return_const(fake_ip);
        resolver
            .expect_exchange()
            .once()
            .return_once(move |_| Ok(upstream));
        if let Some(active) = fake_ip_active {
            resolver
                .expect_fake_ip_active_for()
                .withf(|host| host == "example.com")
                .once()
                .return_const(active);
        }
        Arc::new(resolver)
    }

    #[tokio::test]
    async fn address_query_matrix_keeps_existing_fake_ip_contract() {
        let req = request(RecordType::A);
        let mut resolver = MockClashResolver::new();
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver
            .expect_resolve_v4()
            .withf(|host, enhanced| host == "example.com" && *enhanced)
            .once()
            .return_once(|_, _| Ok(Some(Ipv4Addr::new(198, 18, 0, 2))));
        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let result = exchange_with_resolver(&resolver, &req, true).await.unwrap();
        assert!(
            matches!(result.answers[0].data, RData::A(A(ip)) if ip == Ipv4Addr::new(198, 18, 0, 2))
        );

        let req = request(RecordType::A);
        let mut resolver = MockClashResolver::new();
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver
            .expect_resolve_v4()
            .withf(|host, enhanced| host == "example.com" && !*enhanced)
            .once()
            .return_once(|_, _| Ok(Some(Ipv4Addr::new(203, 0, 113, 7))));
        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let result = exchange_with_resolver(&resolver, &req, false)
            .await
            .unwrap();
        assert!(
            matches!(result.answers[0].data, RData::A(A(ip)) if ip == Ipv4Addr::new(203, 0, 113, 7))
        );

        for (record_type, fake_ip, data) in [
            (
                RecordType::A,
                false,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 7))),
            ),
            (
                RecordType::AAAA,
                true,
                RData::AAAA(AAAA("2001:db8::7".parse().unwrap())),
            ),
        ] {
            let req = request(record_type);
            let resolver = exchanging_resolver(fake_ip, None, response(&req, data));
            let result =
                exchange_with_resolver(&resolver, &req, true).await.unwrap();
            assert_eq!(result.queries[0].query_type(), record_type);
            assert_eq!(result.answers[0].record_type(), record_type);
        }
    }

    #[tokio::test]
    async fn fake_ip_svcb_matrix_preserves_type_and_safe_params() {
        for record_type in [RecordType::HTTPS, RecordType::SVCB] {
            let req = request(record_type);
            let resolver = exchanging_resolver(
                true,
                Some(true),
                response(&req, svc_data(record_type)),
            );

            let result =
                exchange_with_resolver(&resolver, &req, true).await.unwrap();

            assert_eq!(result.queries[0].query_type(), record_type);
            assert_eq!(result.answers[0].record_type(), record_type);
            let params = match &result.answers[0].data {
                RData::HTTPS(https) => &https.0.svc_params,
                RData::SVCB(svcb) => &svcb.svc_params,
                data => panic!("unexpected answer: {data:?}"),
            };
            assert!(!params.iter().any(|(key, _)| matches!(
                key,
                SvcParamKey::Ipv4Hint | SvcParamKey::Ipv6Hint
            )));
            assert!(params.iter().any(|(key, _)| *key == SvcParamKey::Alpn));
            assert!(params.iter().any(|(key, _)| *key == SvcParamKey::Port));
            assert!(
                params
                    .iter()
                    .any(|(key, _)| *key == SvcParamKey::EchConfigList)
            );
            let mandatory = params
                .iter()
                .find_map(|(_, value)| match value {
                    SvcParamValue::Mandatory(Mandatory(keys)) => Some(keys),
                    _ => None,
                })
                .unwrap();
            assert_eq!(mandatory, &vec![SvcParamKey::Alpn]);
        }
    }

    #[tokio::test]
    async fn non_fake_ip_svcb_responses_keep_hints() {
        for record_type in [RecordType::HTTPS, RecordType::SVCB] {
            for (fake_ip, active) in [(false, None), (true, Some(false))] {
                let req = request(record_type);
                let resolver = exchanging_resolver(
                    fake_ip,
                    active,
                    response(&req, svc_data(record_type)),
                );

                let result =
                    exchange_with_resolver(&resolver, &req, true).await.unwrap();
                let params = match &result.answers[0].data {
                    RData::HTTPS(https) => &https.0.svc_params,
                    RData::SVCB(svcb) => &svcb.svc_params,
                    data => panic!("unexpected answer: {data:?}"),
                };
                assert!(params.iter().any(|(key, _)| *key == SvcParamKey::Ipv4Hint));
                assert!(params.iter().any(|(key, _)| *key == SvcParamKey::Ipv6Hint));
            }
        }
    }

    #[test]
    fn stripping_only_mandatory_hints_removes_mandatory() {
        let name = Name::from_ascii("example.com.").unwrap();
        let record = Record::from_rdata(
            name,
            300,
            RData::HTTPS(HTTPS(SVCB::new(
                1,
                Name::root(),
                vec![
                    (
                        SvcParamKey::Mandatory,
                        SvcParamValue::Mandatory(Mandatory(vec![
                            SvcParamKey::Ipv4Hint,
                        ])),
                    ),
                    (
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![A(
                            Ipv4Addr::LOCALHOST,
                        )])),
                    ),
                ],
            ))),
        );

        let RData::HTTPS(https) = strip_svc_ip_hints(&record).data else {
            panic!("expected HTTPS answer");
        };
        assert!(https.0.svc_params.is_empty());
    }
}
