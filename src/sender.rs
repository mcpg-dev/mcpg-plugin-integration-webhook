use std::collections::HashMap;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use tracing::{info, info_span, warn};

use crate::{EndpointConfig, WebhookEvent, WebhookPluginConfig};

/// Per-endpoint circuit breaker state machine. Each endpoint URL has its
/// own breaker so a single broken receiver cannot throttle healthy ones.
#[derive(Debug, Clone)]
enum CircuitState {
    Closed { consecutive_failures: u32 },
    Open { until: Instant },
    HalfOpen { probes_remaining: u32 },
}

impl CircuitState {
    fn label(&self) -> &'static str {
        match self {
            CircuitState::Closed { .. } => "closed",
            CircuitState::Open { .. } => "open",
            CircuitState::HalfOpen { .. } => "half_open",
        }
    }
}

/// Background task that receives webhook events and delivers them via HTTP.
/// Each endpoint URL has its own circuit breaker (Closed -> Open -> HalfOpen)
/// so a single broken receiver cannot throttle healthy ones. Retries use
/// exponential backoff with jitter, clamped to prevent multi-minute sleeps.
pub struct BackgroundSender {
    config: WebhookPluginConfig,
    rx: mpsc::Receiver<(WebhookEvent, Vec<EndpointConfig>)>,
    breakers: HashMap<String, CircuitState>,
}

impl BackgroundSender {
    pub fn new(
        config: WebhookPluginConfig,
        rx: mpsc::Receiver<(WebhookEvent, Vec<EndpointConfig>)>,
    ) -> Self {
        // The HTTP client is built per delivery inside `deliver_with_retry`
        // so the resolved+validated address can be pinned (SSRF guard).
        Self {
            config,
            rx,
            breakers: HashMap::new(),
        }
    }

    pub fn run(mut self) {
        // `recv()` owns the borrow only for the body of each
        // iteration, unlike `iter()` which borrows `self.rx` for the
        // entire loop lifetime — the latter conflicts with the
        // `&mut self` call to `deliver_with_retry` below.
        while let Ok((event, endpoints)) = self.rx.recv() {
            for endpoint in endpoints {
                let payload = match serde_json::to_vec(&event) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(error = %e, "failed to serialize webhook event");
                        continue;
                    }
                };

                self.deliver_with_retry(&endpoint, &payload);
            }
        }
        info!("webhook background sender shutting down");
    }

    /// Check whether the circuit breaker for this endpoint allows a delivery attempt.
    /// In Open state, transitions to HalfOpen once the cooldown expires.
    fn breaker_allow(&mut self, url: &str) -> bool {
        let cb = &self.config.circuit_breaker;
        let entry = self
            .breakers
            .entry(url.to_owned())
            .or_insert(CircuitState::Closed {
                consecutive_failures: 0,
            });

        match entry {
            CircuitState::Closed { .. } => true,
            CircuitState::Open { until } => {
                if Instant::now() >= *until {
                    *entry = CircuitState::HalfOpen {
                        probes_remaining: cb.half_open_probe_count.max(1),
                    };
                    Self::record_state(url, entry);
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen { probes_remaining } => {
                if *probes_remaining > 0 {
                    *probes_remaining -= 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Reset the circuit breaker to Closed on a successful delivery.
    fn record_success(&mut self, url: &str) {
        let next = CircuitState::Closed {
            consecutive_failures: 0,
        };
        self.breakers.insert(url.to_owned(), next.clone());
        Self::record_state(url, &next);
    }

    /// Record a delivery failure. Transitions Closed -> Open after threshold,
    /// or re-opens immediately on HalfOpen probe failure.
    fn record_failure(&mut self, url: &str) {
        let cb = &self.config.circuit_breaker;
        let current = self.breakers.remove(url).unwrap_or(CircuitState::Closed {
            consecutive_failures: 0,
        });
        let next = match current {
            CircuitState::Closed {
                consecutive_failures,
            } => {
                let n = consecutive_failures + 1;
                if n >= cb.consecutive_5xx_threshold.max(1) {
                    CircuitState::Open {
                        until: Instant::now() + Duration::from_millis(cb.open_duration_ms.max(1)),
                    }
                } else {
                    CircuitState::Closed {
                        consecutive_failures: n,
                    }
                }
            }
            // HalfOpen probe failed → re-open immediately.
            CircuitState::HalfOpen { .. } | CircuitState::Open { .. } => CircuitState::Open {
                until: Instant::now() + Duration::from_millis(cb.open_duration_ms.max(1)),
            },
        };
        Self::record_state(url, &next);
        self.breakers.insert(url.to_owned(), next);
    }

    fn record_state(url: &str, state: &CircuitState) {
        metrics::gauge!(
            "mcpg_webhook_circuit_state",
            "endpoint" => url.to_owned(),
            "state" => state.label(),
        )
        .set(1.0);
    }

    /// Resolve the endpoint host, reject private/loopback targets (unless the
    /// endpoint opts in), and return a client with the validated address
    /// pinned and redirects disabled. `None` means the event is dropped
    /// (fail-closed) — the caller returns without sending.
    fn build_pinned_client(
        &self,
        url: &str,
        allow_private_backends: bool,
    ) -> Option<reqwest::blocking::Client> {
        use std::net::ToSocketAddrs;
        // A parse failure must not echo the URL (it may carry userinfo).
        let parsed = match url::Url::parse(url) {
            Ok(p) => p,
            Err(_) => {
                warn!("webhook: endpoint URL failed to parse; dropping event");
                return None;
            }
        };
        let host = match parsed.host_str() {
            Some(h) => h.to_owned(),
            None => {
                warn!("webhook: endpoint URL has no host; dropping event");
                return None;
            }
        };
        let Some(port) = parsed.port_or_known_default() else {
            warn!(host = %host, "webhook: endpoint URL has no port/default; dropping event");
            return None;
        };
        let addrs: Vec<std::net::SocketAddr> = match (host.as_str(), port).to_socket_addrs() {
            Ok(it) => it.collect(),
            Err(_) => {
                warn!(host = %host, "webhook: DNS resolution failed; dropping event");
                metrics::counter!("mcpg_dns_rebinding_blocked_total", "host" => host.clone())
                    .increment(1);
                return None;
            }
        };
        if addrs.is_empty() {
            warn!(host = %host, "webhook: host resolved to no addresses; dropping event");
            return None;
        }
        let chosen = if allow_private_backends {
            addrs[0]
        } else {
            match addrs
                .iter()
                .find(|a| !mcpg_plugin_protocol::security::is_private_address(&a.ip()))
                .copied()
            {
                Some(addr) => addr,
                None => {
                    warn!(
                        host = %host,
                        "webhook: host resolves only to private/loopback addresses; dropping \
                         event (set allow_private_backends=true to permit)"
                    );
                    metrics::counter!("mcpg_dns_rebinding_blocked_total", "host" => host.clone())
                        .increment(1);
                    return None;
                }
            }
        };
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(self.config.timeout_ms))
            .pool_max_idle_per_host(5)
            .resolve(&host, chosen)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()
            .or_else(|| {
                warn!(host = %host, "webhook: failed to build pinned client; dropping event");
                None
            })
    }

    /// Deliver a webhook event to an endpoint with circuit breaker gating,
    /// exponential backoff retry, and DNS rebinding protection on responses.
    fn deliver_with_retry(&mut self, endpoint: &EndpointConfig, payload: &[u8]) {
        // The gateway substitutes `${env.X}` / `cred://…` in the
        // endpoint config at load, so URL and headers arrive already
        // resolved and are used verbatim.
        let url = endpoint.url.clone();

        // Wrap delivery in a plugin-scoped span so operators can
        // correlate per-endpoint retry / outcome events with the
        // originating webhook event.
        let _delivery_span = info_span!(
            "webhook_deliver",
            plugin_id = "dev.mcpg.integration.webhook",
            endpoint = %url,
        )
        .entered();

        if !self.breaker_allow(&url) {
            metrics::counter!(
                "mcpg_webhook_circuit_short_circuited_total",
                "endpoint" => url.clone(),
            )
            .increment(1);
            return;
        }

        // SSRF guard: resolve the host and pin the validated address into a
        // per-delivery client (redirects disabled), so a DNS rebind or a 30x
        // to an internal host cannot reach a private address. Fail closed
        // before any send unless the endpoint opts into private targets.
        let client = match self.build_pinned_client(&url, endpoint.allow_private_backends) {
            Some(client) => client,
            None => return,
        };

        let mut attempt = 0u32;

        loop {
            let mut req = client
                .post(&url)
                .header("content-type", "application/json")
                .body(payload.to_vec());

            for (k, v) in &endpoint.headers {
                req = req.header(k.as_str(), v.as_str());
            }

            // Per-attempt latency histogram so operators can spot
            // endpoints whose response time degrades before they
            // fail outright.
            let req_started = Instant::now();
            let response = req.send();
            let elapsed_ms = req_started.elapsed().as_millis() as f64;
            metrics::histogram!(
                "mcpg_webhook_request_duration_ms",
                "endpoint" => url.clone(),
            )
            .record(elapsed_ms);
            let is_5xx = match response {
                Ok(resp) => {
                    // Security: DNS rebinding guard — reject delivery to private IPs.
                    if let Err(e) = mcpg_plugin_protocol::security::check_response_remote_addr(
                        resp.remote_addr(),
                        endpoint.allow_private_backends,
                    ) {
                        warn!(url = %url, error = %e, "webhook DNS rebinding blocked");
                        metrics::counter!(
                            "mcpg_dns_rebinding_blocked_total",
                            "host" => url.clone(),
                        )
                        .increment(1);
                        return;
                    }
                    if resp.status().is_success() {
                        self.record_success(&url);
                        return;
                    }
                    let status = resp.status();
                    warn!(
                        url = %url,
                        status = %status,
                        attempt = attempt + 1,
                        "webhook delivery failed"
                    );
                    status.is_server_error()
                }
                Err(e) => {
                    warn!(
                        url = %url,
                        error = %e,
                        attempt = attempt + 1,
                        "webhook delivery error"
                    );
                    // Treat network-level errors as 5xx-equivalent for the breaker.
                    true
                }
            };

            if is_5xx {
                self.record_failure(&url);
            }

            attempt += 1;
            if attempt > self.config.max_retries {
                warn!(
                    url = %url,
                    max_retries = self.config.max_retries,
                    "webhook delivery exhausted retries"
                );
                return;
            }

            // Exponential backoff with +/-20% jitter. Clamped so a
            // misconfigured base cannot produce multi-minute sleeps.
            let base = self
                .config
                .retry_backoff_ms
                .saturating_mul(2u64.saturating_pow(attempt - 1));
            let jitter = {
                let pct = (std::time::UNIX_EPOCH
                    .elapsed()
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
                    % 40) as i64
                    - 20;
                (base as i64 * pct / 100).max(-(base as i64 / 2))
            };
            let sleep_ms = (base as i64 + jitter).max(1) as u64;
            metrics::histogram!(
                "mcpg_webhook_backoff_applied_ms",
                "endpoint" => url.clone(),
            )
            .record(sleep_ms as f64);
            std::thread::sleep(Duration::from_millis(sleep_ms));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_opens_after_threshold_failures() {
        let (_tx, rx) = mpsc::sync_channel(1);
        let cfg = WebhookPluginConfig {
            endpoints: vec![],
            max_retries: 0,
            retry_backoff_ms: 1,
            timeout_ms: 1000,
            buffer_size: 1,
            circuit_breaker: crate::CircuitBreakerConfig {
                consecutive_5xx_threshold: 3,
                open_duration_ms: 60,
                half_open_probe_count: 1,
            },
        };
        let mut s = BackgroundSender::new(cfg, rx);
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
        let (_tx, rx) = mpsc::sync_channel(1);
        let cfg = WebhookPluginConfig {
            endpoints: vec![],
            max_retries: 0,
            retry_backoff_ms: 1,
            timeout_ms: 1000,
            buffer_size: 1,
            circuit_breaker: crate::CircuitBreakerConfig {
                consecutive_5xx_threshold: 1,
                open_duration_ms: 1,
                half_open_probe_count: 1,
            },
        };
        let mut s = BackgroundSender::new(cfg, rx);
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
        let (_tx, rx) = mpsc::sync_channel(1);
        BackgroundSender::new(WebhookPluginConfig::default(), rx)
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
}
