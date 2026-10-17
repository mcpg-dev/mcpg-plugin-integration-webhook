use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;

use mcpg_standard_webhooks::{HEADER_SIGNATURE, Verifier};
use reqwest::header::HeaderName;

use super::*;
use crate::CircuitBreakerConfig;

const NEW: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const OLD: &str = "whsec_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const BODY: &[u8] = br#"{"event":"tool_call_completed"}"#;

/// One request as a receiver read it.
struct Received {
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Received {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn timestamp(&self) -> u64 {
        self.header(HEADER_TIMESTAMP).unwrap().parse().unwrap()
    }

    fn verify(&self, secrets: &[&str]) -> bool {
        let secrets = secrets
            .iter()
            .map(|s| WhsecSecret::parse(s).unwrap())
            .collect();
        Verifier::new(secrets)
            .unwrap()
            .verify_headers(&self.headers, &self.body, self.timestamp())
            .is_ok()
    }
}

/// A receiver on 127.0.0.1 that answers each request with the next of
/// `statuses`, then `200`.
struct Receiver {
    url: String,
    seen: Arc<Mutex<Vec<Received>>>,
}

impl Receiver {
    fn start(statuses: &'static [u16]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let mut statuses = statuses.iter().copied();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(request) = read_request(&mut stream) else {
                    continue;
                };
                log.lock().unwrap().push(request);
                let status = statuses.next().unwrap_or(200);
                let reply = format!(
                    "HTTP/1.1 {status} Test\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        Self { url, seen }
    }

    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    fn take(&self) -> Vec<Received> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }

    /// Wait until `n` requests have arrived, for a delivery made on the
    /// background thread.
    fn wait_for(&self, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.count() < n {
            assert!(
                Instant::now() < deadline,
                "{} of {n} requests",
                self.count()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Received> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_len = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = std::str::from_utf8(&buf[..head_len]).ok()?;
    let mut headers = HeaderMap::new();
    for line in head.split("\r\n").skip(1).filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':')?;
        headers.append(
            HeaderName::from_bytes(name.trim().as_bytes()).ok()?,
            HeaderValue::from_str(value.trim()).ok()?,
        );
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_len..].to_vec();
    while body.len() < len {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(Received { headers, body })
}

fn endpoint(url: &str, secrets: &[&str]) -> EndpointConfig {
    EndpointConfig {
        url: url.to_owned(),
        events: vec![],
        slow_threshold_ms: None,
        headers: [("x-static".to_owned(), "kept".to_owned())].into(),
        signing_secrets: secrets
            .iter()
            .map(|s| WhsecSecret::parse(s).unwrap())
            .collect(),
        allow_private_backends: true,
    }
}

fn config(endpoints: Vec<EndpointConfig>, max_retries: u32) -> WebhookPluginConfig {
    WebhookPluginConfig {
        endpoints,
        max_retries,
        // Above 1250 ms, so that even with -20% jitter a retry lands in a
        // later second and carries another timestamp.
        retry_backoff_ms: 1_300,
        timeout_ms: 5_000,
        buffer_size: 16,
        circuit_breaker: CircuitBreakerConfig::default(),
    }
}

fn sender(config: WebhookPluginConfig) -> BackgroundSender {
    let (_tx, rx) = mpsc::sync_channel(1);
    BackgroundSender::new(Arc::new(config), rx)
}

#[test]
fn a_delivery_is_signed_per_standard_webhooks() {
    let hook = Receiver::start(&[]);
    let mut s = sender(config(vec![endpoint(&hook.url, &[NEW])], 0));
    s.deliver_with_retry(0, "msg_0192abc", BODY);
    let got = hook.take();
    assert_eq!(got.len(), 1);
    let request = &got[0];
    assert_eq!(request.body, BODY);
    assert_eq!(request.header(HEADER_ID), Some("msg_0192abc"));
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(request.header("x-static"), Some("kept"));
    assert!(request.timestamp().abs_diff(unix_now()) <= 5);
    assert!(request.verify(&[NEW]));
    assert!(!request.verify(&[OLD]));
}

#[test]
fn a_rotation_signs_with_every_secret() {
    let hook = Receiver::start(&[]);
    let mut s = sender(config(vec![endpoint(&hook.url, &[NEW, OLD])], 0));
    s.deliver_with_retry(0, "msg_rotation", BODY);
    let got = hook.take();
    let request = &got[0];
    let signature = request.header(HEADER_SIGNATURE).unwrap();
    assert_eq!(signature.split(' ').count(), 2);
    assert!(request.verify(&[NEW]));
    assert!(request.verify(&[OLD]));
}

#[test]
fn a_retry_keeps_the_id_and_signs_again_at_its_own_time() {
    let hook = Receiver::start(&[500, 200]);
    let mut s = sender(config(vec![endpoint(&hook.url, &[NEW])], 3));
    s.deliver_with_retry(0, "msg_retried", BODY);
    let got = hook.take();
    assert_eq!(got.len(), 2, "one failure, then the delivery");
    assert_eq!(got[0].header(HEADER_ID), Some("msg_retried"));
    assert_eq!(got[1].header(HEADER_ID), Some("msg_retried"));
    assert_ne!(got[0].timestamp(), got[1].timestamp());
    assert_ne!(
        got[0].header(HEADER_SIGNATURE),
        got[1].header(HEADER_SIGNATURE)
    );
    assert!(got.iter().all(|r| r.verify(&[NEW])));
}

#[test]
fn gone_stops_that_endpoint_and_no_other() {
    let gone = Receiver::start(&[410]);
    let live = Receiver::start(&[]);
    let mut s = sender(config(
        vec![endpoint(&gone.url, &[NEW]), endpoint(&live.url, &[NEW])],
        3,
    ));
    for id in ["msg_first", "msg_second"] {
        s.deliver_with_retry(0, id, BODY);
        s.deliver_with_retry(1, id, BODY);
    }
    assert_eq!(gone.count(), 1, "no retry, and nothing after the 410");
    assert_eq!(live.count(), 2);
    assert_eq!(s.gone, [true, false]);
}

#[test]
fn too_large_drops_the_event_without_a_retry() {
    let hook = Receiver::start(&[413]);
    let mut s = sender(config(vec![endpoint(&hook.url, &[NEW])], 3));
    s.deliver_with_retry(0, "msg_big", BODY);
    assert_eq!(hook.count(), 1);
    s.deliver_with_retry(0, "msg_next", BODY);
    let got = hook.take();
    assert_eq!(got.len(), 2, "the endpoint still takes the next event");
    assert_eq!(got[1].header(HEADER_ID), Some("msg_next"));
}

#[test]
fn too_large_closes_a_half_open_breaker() {
    let hook = Receiver::start(&[413]);
    let mut s = sender(config(vec![endpoint(&hook.url, &[NEW])], 3));
    s.breakers.insert(
        hook.url.clone(),
        CircuitState::HalfOpen {
            probes_remaining: 1,
            since: Instant::now(),
        },
    );
    s.deliver_with_retry(0, "msg_big", BODY);
    assert!(matches!(
        s.breakers.get(&hook.url),
        Some(CircuitState::Closed {
            consecutive_failures: 0
        })
    ));
    s.deliver_with_retry(0, "msg_next", BODY);
    assert_eq!(hook.count(), 2, "the breaker admits the next event");
}

#[test]
fn spent_half_open_probes_are_admitted_again_after_the_cooldown() {
    let mut s = sender(WebhookPluginConfig {
        circuit_breaker: CircuitBreakerConfig {
            consecutive_5xx_threshold: 1,
            open_duration_ms: 1_000,
            half_open_probe_count: 1,
        },
        ..WebhookPluginConfig::default()
    });
    let url = "https://example.test/hook";
    s.breakers.insert(
        url.to_owned(),
        CircuitState::HalfOpen {
            probes_remaining: 0,
            since: Instant::now(),
        },
    );
    assert!(!s.breaker_allow(url), "within the cooldown");
    s.breakers.insert(
        url.to_owned(),
        CircuitState::HalfOpen {
            probes_remaining: 0,
            since: Instant::now() - Duration::from_secs(2),
        },
    );
    assert!(s.breaker_allow(url), "a new probe after the cooldown");
    assert!(!s.breaker_allow(url), "one probe per cooldown");
}

#[test]
fn an_endpoint_without_secrets_gets_the_id_and_timestamp_only() {
    let hook = Receiver::start(&[]);
    let mut s = sender(config(vec![endpoint(&hook.url, &[])], 0));
    s.deliver_with_retry(0, "msg_plain", BODY);
    let got = hook.take();
    let request = &got[0];
    assert_eq!(request.header(HEADER_ID), Some("msg_plain"));
    assert!(request.timestamp().abs_diff(unix_now()) <= 5);
    assert_eq!(request.header(HEADER_SIGNATURE), None);
}

#[test]
fn one_event_has_one_id_on_every_endpoint() {
    let (a, b) = (Receiver::start(&[]), Receiver::start(&[]));
    let plugin = crate::WebhookPlugin::new(config(
        vec![endpoint(&a.url, &[NEW]), endpoint(&b.url, &[])],
        0,
    ));
    plugin.enqueue(
        crate::WebhookEvent::SlowResponse {
            tool_name: "t".to_owned(),
            request_id: "r".to_owned(),
            duration_ms: 2,
            threshold_ms: 1,
        },
        vec![0, 1],
    );
    a.wait_for(1);
    b.wait_for(1);
    let (a, b) = (a.take(), b.take());
    let id = a[0].header(HEADER_ID).unwrap();
    assert_eq!(b[0].header(HEADER_ID), Some(id));
    let hex = id.strip_prefix("msg_").unwrap();
    assert_eq!(hex.len(), 32);
    assert!(hex.bytes().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(
        uuid::Uuid::parse_str(hex).unwrap().get_version_num(),
        7,
        "{id}"
    );
    assert!(a[0].verify(&[NEW]));
}

#[test]
fn circuit_opens_after_threshold_failures() {
    let mut s = sender(WebhookPluginConfig {
        endpoints: vec![],
        max_retries: 0,
        retry_backoff_ms: 1,
        timeout_ms: 1000,
        buffer_size: 1,
        circuit_breaker: CircuitBreakerConfig {
            consecutive_5xx_threshold: 3,
            open_duration_ms: 60,
            half_open_probe_count: 1,
        },
    });
    let url = "https://example.test/hook";

    for _ in 0..3 {
        assert!(s.breaker_allow(url));
        s.record_failure(url);
    }
    assert!(
        !s.breaker_allow(url),
        "breaker should be Open after threshold"
    );
}

#[test]
fn circuit_half_open_returns_to_closed_on_success() {
    let mut s = sender(WebhookPluginConfig {
        endpoints: vec![],
        max_retries: 0,
        retry_backoff_ms: 1,
        timeout_ms: 1000,
        buffer_size: 1,
        circuit_breaker: CircuitBreakerConfig {
            consecutive_5xx_threshold: 1,
            open_duration_ms: 1,
            half_open_probe_count: 1,
        },
    });
    let url = "https://example.test/hook";

    assert!(s.breaker_allow(url));
    s.record_failure(url);
    // Force-expire the open window by rewriting the state directly.
    s.breakers.insert(
        url.to_owned(),
        CircuitState::Open {
            until: Instant::now() - Duration::from_secs(1),
        },
    );
    // Next allow() should transition to HalfOpen and admit a probe.
    assert!(s.breaker_allow(url));
    s.record_success(url);
    // Breaker should be closed again and admit traffic.
    assert!(s.breaker_allow(url));
}

fn sender_for_pin_test() -> BackgroundSender {
    sender(WebhookPluginConfig::default())
}

#[test]
fn build_pinned_client_blocks_loopback_by_default() {
    let s = sender_for_pin_test();
    // 127.0.0.1 is loopback → private; resolution+select must fail closed.
    assert!(
        s.build_pinned_client("http://127.0.0.1:9/hook", false)
            .is_none()
    );
}

#[test]
fn build_pinned_client_blocks_link_local_metadata_by_default() {
    let s = sender_for_pin_test();
    assert!(
        s.build_pinned_client("http://169.254.169.254/latest/meta-data", false)
            .is_none()
    );
}

#[test]
fn build_pinned_client_opt_in_allows_loopback() {
    let s = sender_for_pin_test();
    // The escape hatch yields a usable (address-pinned) client.
    assert!(
        s.build_pinned_client("http://127.0.0.1:9/hook", true)
            .is_some()
    );
}

#[test]
fn build_pinned_client_rejects_unparseable_url() {
    let s = sender_for_pin_test();
    assert!(s.build_pinned_client("not a url", false).is_none());
}
