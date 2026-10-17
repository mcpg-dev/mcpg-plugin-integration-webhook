use std::collections::HashMap;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mcpg_standard_webhooks::{HEADER_ID, HEADER_TIMESTAMP, WhsecSecret, sign_message};
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderValue};
use tracing::{error, info, info_span, warn};

use crate::{EndpointConfig, Outgoing, WebhookPluginConfig};

/// Per-endpoint circuit breaker state machine. Each endpoint URL has its
/// own breaker so a single broken receiver cannot throttle healthy ones.
#[derive(Debug, Clone)]
enum CircuitState {
    Closed {
        consecutive_failures: u32,
    },
    Open {
        until: Instant,
    },
    HalfOpen {
        probes_remaining: u32,
        since: Instant,
    },
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

/// What one attempt's answer means for the delivery.
enum Attempt {
    Delivered,
    /// Stop: the receiver answered, but refused this event, or the
    /// endpoint, for good.
    Stop,
    /// Try again after a backoff; `server_side` counts against the breaker.
    Retry {
        server_side: bool,
    },
}

/// Background task that receives webhook events and delivers them via HTTP.
/// Each endpoint URL has its own circuit breaker (Closed -> Open -> HalfOpen)
/// so a single broken receiver cannot throttle healthy ones. Retries use
/// exponential backoff with jitter, clamped to prevent multi-minute sleeps.
pub struct BackgroundSender {
    config: Arc<WebhookPluginConfig>,
    rx: mpsc::Receiver<Outgoing>,
    breakers: HashMap<String, CircuitState>,
    /// Endpoints that answered `410 Gone`, by index. They get nothing more
    /// until the plugin is loaded again.
    gone: Vec<bool>,
}

impl BackgroundSender {
    pub(crate) fn new(config: Arc<WebhookPluginConfig>, rx: mpsc::Receiver<Outgoing>) -> Self {
        // The HTTP client is built per delivery inside `deliver_with_retry`
        // so the resolved+validated address can be pinned (SSRF guard).
        let gone = vec![false; config.endpoints.len()];
        Self {
            config,
            rx,
            breakers: HashMap::new(),
            gone,
        }
    }

    pub fn run(mut self) {
        // `recv()` owns the borrow only for the body of each
        // iteration, unlike `iter()` which borrows `self.rx` for the
        // entire loop lifetime — the latter conflicts with the
        // `&mut self` call to `deliver_with_retry` below.
        while let Ok(outgoing) = self.rx.recv() {
            let payload = match serde_json::to_vec(&outgoing.event) {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "failed to serialize webhook event");
                    continue;
                }
            };
            for index in outgoing.endpoints {
                self.deliver_with_retry(index, &outgoing.msg_id, &payload);
            }
        }
        info!("webhook background sender shutting down");
    }

    /// Check whether the circuit breaker for this endpoint allows a delivery attempt.
    /// In Open state, transitions to HalfOpen once the cooldown expires.
    fn breaker_allow(&mut self, url: &str) -> bool {
        let cb = &self.config.circuit_breaker;
        let open_for = Duration::from_millis(cb.open_duration_ms.max(1));
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
                        since: Instant::now(),
                    };
                    Self::record_state(url, entry);
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen {
                probes_remaining,
                since,
            } => {
                // Deliveries run one at a time, so spent probes here ended
                // without a verdict; admit new ones after another cooldown.
                if *probes_remaining == 0 && since.elapsed() >= open_for {
                    *probes_remaining = cb.half_open_probe_count.max(1);
                    *since = Instant::now();
                }
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

    /// Deliver one event to the endpoint at `index` with circuit breaker
    /// gating, exponential backoff retry, and DNS rebinding protection on
    /// responses. Every attempt carries `msg_id` and its own timestamp and
    /// signature.
    fn deliver_with_retry(&mut self, index: usize, msg_id: &str, payload: &[u8]) {
        let config = Arc::clone(&self.config);
        let Some(endpoint) = config.endpoints.get(index) else {
            return;
        };
        if self.gone.get(index).copied().unwrap_or(false) {
            return;
        }
        // The gateway substitutes `${env.X}` / `cred://…` in the
        // endpoint config at load, so URL and headers arrive already
        // resolved and are used verbatim.
        let url = endpoint.url.as_str();

        // Wrap delivery in a plugin-scoped span so operators can
        // correlate per-endpoint retry / outcome events with the
        // originating webhook event. The span names the endpoint by its
        // index: every line logged inside it carries the span's fields.
        let _delivery_span = info_span!(
            "webhook_deliver",
            plugin_id = "dev.mcpg.integration.webhook",
            endpoint_index = index,
        )
        .entered();

        if !self.breaker_allow(url) {
            metrics::counter!(
                "mcpg_webhook_circuit_short_circuited_total",
                "endpoint" => url.to_owned(),
            )
            .increment(1);
            return;
        }

        // SSRF guard: resolve the host and pin the validated address into a
        // per-delivery client (redirects disabled), so a DNS rebind or a 30x
        // to an internal host cannot reach a private address. Fail closed
        // before any send unless the endpoint opts into private targets.
        let client = match self.build_pinned_client(url, endpoint.allow_private_backends) {
            Some(client) => client,
            None => return,
        };

        let mut attempt = 0u32;

        loop {
            let Some(webhook_headers) = webhook_headers(endpoint, msg_id, unix_now(), payload)
            else {
                warn!(
                    endpoint_index = index,
                    "webhook: message id is not header-safe; dropping event"
                );
                return;
            };
            let mut req = client
                .post(url)
                .header("content-type", "application/json")
                .body(payload.to_vec());

            for (k, v) in &endpoint.headers {
                req = req.header(k.as_str(), v.as_str());
            }
            req = req.headers(webhook_headers);

            // Per-attempt latency histogram so operators can spot
            // endpoints whose response time degrades before they
            // fail outright.
            let req_started = Instant::now();
            let response = req.send();
            let elapsed_ms = req_started.elapsed().as_millis() as f64;
            metrics::histogram!(
                "mcpg_webhook_request_duration_ms",
                "endpoint" => url.to_owned(),
            )
            .record(elapsed_ms);
            let outcome = match response {
                Ok(resp) => {
                    // Security: DNS rebinding guard — reject delivery to private IPs.
                    if let Err(e) = mcpg_plugin_protocol::security::check_response_remote_addr(
                        resp.remote_addr(),
                        endpoint.allow_private_backends,
                    ) {
                        warn!(url = %url, error = %e, "webhook DNS rebinding blocked");
                        metrics::counter!(
                            "mcpg_dns_rebinding_blocked_total",
                            "host" => url.to_owned(),
                        )
                        .increment(1);
                        return;
                    }
                    self.judge(index, resp.status(), attempt)
                }
                Err(e) => {
                    warn!(
                        url = %url,
                        error = %e,
                        attempt = attempt + 1,
                        "webhook delivery error"
                    );
                    // Treat network-level errors as 5xx-equivalent for the breaker.
                    Attempt::Retry { server_side: true }
                }
            };

            match outcome {
                // Either way the receiver answered, so the endpoint is up.
                Attempt::Delivered | Attempt::Stop => {
                    self.record_success(url);
                    return;
                }
                Attempt::Retry { server_side } => {
                    if server_side {
                        self.record_failure(url);
                    }
                }
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
                "endpoint" => url.to_owned(),
            )
            .record(sleep_ms as f64);
            std::thread::sleep(Duration::from_millis(sleep_ms));
        }
    }

    /// Only a `2xx` delivers. `410 Gone` stops the endpoint, as Standard
    /// Webhooks asks of a sender; `413` drops the event, since the same
    /// bytes are always too large; anything else is retried.
    fn judge(&mut self, index: usize, status: StatusCode, attempt: u32) -> Attempt {
        if status.is_success() {
            return Attempt::Delivered;
        }
        match status {
            StatusCode::GONE => {
                if let Some(gone) = self.gone.get_mut(index) {
                    *gone = true;
                }
                error!(
                    endpoint_index = index,
                    "webhook endpoint answered 410 Gone; sending it nothing more until the \
                     configuration reloads"
                );
                metrics::counter!(
                    "mcpg_webhook_gone_total",
                    "endpoint_index" => index.to_string(),
                )
                .increment(1);
                Attempt::Stop
            }
            StatusCode::PAYLOAD_TOO_LARGE => {
                warn!(
                    endpoint_index = index,
                    "webhook endpoint answered 413; dropping the event without a retry"
                );
                Attempt::Stop
            }
            _ => {
                warn!(
                    endpoint_index = index,
                    status = %status,
                    attempt = attempt + 1,
                    "webhook delivery failed"
                );
                Attempt::Retry {
                    server_side: status.is_server_error(),
                }
            }
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The Standard Webhooks headers of one attempt: `webhook-id` and
/// `webhook-timestamp`, and `webhook-signature` when the endpoint has
/// secrets. `None` when `msg_id` is not a valid id.
fn webhook_headers(
    endpoint: &EndpointConfig,
    msg_id: &str,
    timestamp: u64,
    payload: &[u8],
) -> Option<HeaderMap> {
    let mut headers = HeaderMap::new();
    if endpoint.signing_secrets.is_empty() {
        let id = HeaderValue::from_str(msg_id).ok()?;
        headers.insert(HEADER_ID, id);
        headers.insert(HEADER_TIMESTAMP, HeaderValue::from(timestamp));
    } else {
        let secrets: Vec<&WhsecSecret> = endpoint.signing_secrets.iter().collect();
        sign_message(&secrets, msg_id, timestamp, payload)
            .ok()?
            .insert_into(&mut headers)
            .ok()?;
    }
    Some(headers)
}

#[cfg(test)]
#[path = "sender_tests.rs"]
mod tests;
