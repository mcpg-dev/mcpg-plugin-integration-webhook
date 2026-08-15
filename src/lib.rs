//! Webhook notifications plugin — fire-and-forget HTTP POST for
//! tool-call lifecycle events. Ships as `native-cdylib-v1`.

use mcpg_plugin_protocol::{GateDecision, PluginClass, PluginContext, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PLUGIN_ID: &str = "dev.mcpg.webhook";

mod sender;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookPluginConfig {
    #[serde(default)]
    pub endpoints: Vec<EndpointConfig>,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_retry_backoff_ms")]
    pub retry_backoff_ms: u64,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
}

/// Per-endpoint circuit breaker. After `consecutive_5xx_threshold`
/// failures, trips Open for `open_duration_ms`. HalfOpen allows
/// probes through — success returns to Closed, failure re-opens.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_cb_threshold")]
    pub consecutive_5xx_threshold: u32,
    #[serde(default = "default_cb_open_ms")]
    pub open_duration_ms: u64,
    #[serde(default = "default_cb_probes")]
    pub half_open_probe_count: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            consecutive_5xx_threshold: default_cb_threshold(),
            open_duration_ms: default_cb_open_ms(),
            half_open_probe_count: default_cb_probes(),
        }
    }
}

fn default_cb_threshold() -> u32 {
    5
}
fn default_cb_open_ms() -> u64 {
    30000
}
fn default_cb_probes() -> u32 {
    1
}

/// Hard cap on retry attempts — prevents misconfigured webhooks from
/// retrying hundreds of times against a flaky receiver.
pub const WEBHOOK_RETRY_HARD_CAP: u32 = 10;

fn default_max_retries() -> u32 {
    3
}
fn default_retry_backoff_ms() -> u64 {
    1000
}
fn default_timeout_ms() -> u64 {
    5000
}
fn default_buffer_size() -> usize {
    1024
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub slow_threshold_ms: Option<u64>,
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    /// Opt-in: allow delivery to private/loopback/link-local addresses
    /// (SSRF-guard escape hatch for in-cluster receivers).
    #[serde(default)]
    pub allow_private_backends: bool,
}

impl EndpointConfig {
    pub fn matches_event(&self, event: &str) -> bool {
        self.events.is_empty() || self.events.iter().any(|e| e == "all" || e == event)
    }
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WebhookEvent {
    ToolCallCompleted {
        tool_name: String,
        request_id: String,
        duration_ms: u64,
        identity_kind: String,
        subject_id: Option<String>,
    },
    ToolCallError {
        tool_name: String,
        request_id: String,
        error_message: String,
        identity_kind: String,
    },
    SlowResponse {
        tool_name: String,
        request_id: String,
        duration_ms: u64,
        threshold_ms: u64,
    },
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

pub struct WebhookPlugin {
    config: WebhookPluginConfig,
    manifest: PluginManifest,
    tx: std::sync::mpsc::SyncSender<(WebhookEvent, Vec<EndpointConfig>)>,
}

impl WebhookPlugin {
    pub fn new(mut config: WebhookPluginConfig) -> Self {
        // Clamp to prevent operator config from amplifying retries.
        if config.max_retries > WEBHOOK_RETRY_HARD_CAP {
            tracing::warn!(
                configured_max_retries = config.max_retries,
                applied_cap = WEBHOOK_RETRY_HARD_CAP,
                "webhook max_retries capped to WEBHOOK_RETRY_HARD_CAP"
            );
            config.max_retries = WEBHOOK_RETRY_HARD_CAP;
        }
        let buffer_size = config.buffer_size.max(1);
        let (tx, rx) = std::sync::mpsc::sync_channel(buffer_size);

        let bg = sender::BackgroundSender::new(config.clone(), rx);
        std::thread::Builder::new()
            .name("mcpg-webhook-sender".into())
            .spawn(move || bg.run())
            .expect("spawn webhook background sender");

        Self {
            manifest: PluginManifest {
                id: PLUGIN_ID.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                name: "Webhook Notifications".into(),
                plugin_class: PluginClass::ToolGate,
                protocol_version: "1.0".into(),
                license: None,
                required_capabilities: Vec::new(),
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            config,
            tx,
        }
    }

    /// SDK macro factory. Fails CLOSED on a present-but-malformed
    /// operator `config:` block (the FFI `make` slot turns the panic
    /// into a boot rejection); an empty / absent block still yields
    /// `Default` (no endpoints).
    pub fn from_config_json(config_json: &str) -> Self {
        let config: WebhookPluginConfig =
            mcpg_plugin_sdk::fail_closed_config!(config_json, WebhookPluginConfig);
        Self::new(config)
    }
}

impl Default for WebhookPluginConfig {
    fn default() -> Self {
        Self {
            endpoints: Vec::new(),
            max_retries: default_max_retries(),
            retry_backoff_ms: default_retry_backoff_ms(),
            timeout_ms: default_timeout_ms(),
            buffer_size: default_buffer_size(),
            circuit_breaker: CircuitBreakerConfig::default(),
        }
    }
}

impl WebhookPlugin {
    /// Best-effort drain budget on shutdown. We cannot hard-stop
    /// the background sender without a Notify because the original
    /// spawn discarded its JoinHandle; sleeping this long lets the
    /// queue flush against healthy receivers and reduces event loss on
    /// SIGTERM. True graceful shutdown that races against a broken
    /// receiver still requires the adapter to time out on its own.
    const SHUTDOWN_DRAIN_BUDGET_MS: u64 = 1_000;
}

impl SyncToolGate for WebhookPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn shutdown(&self) {
        tracing::info!(
            drain_budget_ms = Self::SHUTDOWN_DRAIN_BUDGET_MS,
            "webhook plugin draining pending events"
        );
        std::thread::sleep(std::time::Duration::from_millis(
            Self::SHUTDOWN_DRAIN_BUDGET_MS,
        ));
    }

    fn evaluate_pre(
        &self,
        _ctx: &PluginContext,
        _arguments: &Value,
        _meta: Option<&Value>,
        _config: &Value,
    ) -> GateDecision {
        GateDecision::allow()
    }

    fn evaluate_post(
        &self,
        ctx: &PluginContext,
        _arguments: &Value,
        result: &Value,
        duration_ms: u64,
        _config: &Value,
    ) -> GateDecision {
        let is_error = result
            .get("isError")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Check for slow responses
        for endpoint in &self.config.endpoints {
            if let Some(threshold) = endpoint.slow_threshold_ms
                && duration_ms > threshold
                && endpoint.matches_event("slow_response")
            {
                let event = WebhookEvent::SlowResponse {
                    tool_name: ctx.tool_name.clone(),
                    request_id: ctx.request_id.clone(),
                    duration_ms,
                    threshold_ms: threshold,
                };
                if self.tx.try_send((event, vec![endpoint.clone()])).is_err() {
                    metrics::counter!("mcpg_webhook_dropped_events_total").increment(1);
                }
            }
        }

        if is_error {
            let error_message = result
                .get("content")
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|item| item.get("text"))
                .and_then(|t| t.as_str())
                .unwrap_or("unknown error")
                .to_owned();

            let event = WebhookEvent::ToolCallError {
                tool_name: ctx.tool_name.clone(),
                request_id: ctx.request_id.clone(),
                error_message,
                identity_kind: ctx.identity.kind.clone(),
            };
            let matching: Vec<_> = self
                .config
                .endpoints
                .iter()
                .filter(|e| e.matches_event("error"))
                .cloned()
                .collect();
            if !matching.is_empty() && self.tx.try_send((event, matching)).is_err() {
                metrics::counter!("mcpg_webhook_dropped_events_total").increment(1);
            }
        } else {
            let event = WebhookEvent::ToolCallCompleted {
                tool_name: ctx.tool_name.clone(),
                request_id: ctx.request_id.clone(),
                duration_ms,
                identity_kind: ctx.identity.kind.clone(),
                subject_id: ctx.identity.subject_id.clone(),
            };
            let matching: Vec<_> = self
                .config
                .endpoints
                .iter()
                .filter(|e| e.matches_event("completed") || e.matches_event("all"))
                .cloned()
                .collect();
            if !matching.is_empty() && self.tx.try_send((event, matching)).is_err() {
                metrics::counter!("mcpg_webhook_dropped_events_total").increment(1);
            }
        }

        GateDecision::allow()
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: WebhookPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| WebhookPlugin::from_config_json(cfg),
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::PluginIdentity;

    fn test_ctx() -> PluginContext {
        PluginContext {
            surface: "tool".to_owned(),
            request_id: "req-001".to_owned(),
            session_id: Some("sess-001".to_owned()),
            tool_name: "test_tool".to_owned(),
            identity: PluginIdentity {
                kind: "verified".to_owned(),
                subject_id: Some("user@example.com".to_owned()),
                trust_level: "verified".to_owned(),
                auth_provider: None,
                issuer: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: Default::default(),
            },
            transport: "http".to_owned(),
        }
    }

    #[test]
    fn endpoint_matches_all() {
        let ep = EndpointConfig {
            url: "http://localhost".to_owned(),
            events: vec!["all".to_owned()],
            slow_threshold_ms: None,
            headers: Default::default(),
            allow_private_backends: false,
        };
        assert!(ep.matches_event("error"));
        assert!(ep.matches_event("completed"));
    }

    #[test]
    fn endpoint_matches_specific() {
        let ep = EndpointConfig {
            url: "http://localhost".to_owned(),
            events: vec!["error".to_owned()],
            slow_threshold_ms: None,
            headers: Default::default(),
            allow_private_backends: false,
        };
        assert!(ep.matches_event("error"));
        assert!(!ep.matches_event("completed"));
    }

    #[test]
    fn endpoint_empty_events_matches_all() {
        let ep = EndpointConfig {
            url: "http://localhost".to_owned(),
            events: vec![],
            slow_threshold_ms: None,
            headers: Default::default(),
            allow_private_backends: false,
        };
        assert!(ep.matches_event("anything"));
    }

    #[test]
    fn always_returns_allow() {
        let plugin = WebhookPlugin::new(WebhookPluginConfig {
            endpoints: vec![],
            max_retries: 0,
            retry_backoff_ms: 100,
            timeout_ms: 1000,
            buffer_size: 16,
            circuit_breaker: CircuitBreakerConfig::default(),
        });
        let ctx = test_ctx();
        let args = serde_json::json!({});
        let result = serde_json::json!({"content": [{"type": "text", "text": "ok"}]});
        let decision = plugin.evaluate_post(&ctx, &args, &result, 100, &Value::Null);
        assert!(matches!(decision, GateDecision::Allow { .. }));
    }

    #[test]
    fn manifest_is_correct() {
        let plugin = WebhookPlugin::new(WebhookPluginConfig {
            endpoints: vec![],
            max_retries: 0,
            retry_backoff_ms: 100,
            timeout_ms: 1000,
            buffer_size: 16,
            circuit_breaker: CircuitBreakerConfig::default(),
        });
        let m = plugin.manifest();
        assert_eq!(m.id, "dev.mcpg.webhook");
        assert_eq!(m.plugin_class, PluginClass::ToolGate);
    }

    #[test]
    fn webhook_event_serializes() {
        let event = WebhookEvent::ToolCallCompleted {
            tool_name: "test".to_owned(),
            request_id: "req-1".to_owned(),
            duration_ms: 123,
            identity_kind: "verified".to_owned(),
            subject_id: Some("user@ex.com".to_owned()),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("tool_call_completed"));
    }

    #[test]
    fn error_event_serializes() {
        let event = WebhookEvent::ToolCallError {
            tool_name: "test".to_owned(),
            request_id: "req-1".to_owned(),
            error_message: "boom".to_owned(),
            identity_kind: "anonymous".to_owned(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("tool_call_error"));
    }

    #[test]
    fn slow_event_serializes() {
        let event = WebhookEvent::SlowResponse {
            tool_name: "test".to_owned(),
            request_id: "req-1".to_owned(),
            duration_ms: 6000,
            threshold_ms: 5000,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("slow_response"));
    }

    #[test]
    fn empty_config_yields_defaults() {
        // An empty / absent operator `config:` block opts out (not a
        // typo) and still produces the Default config: no endpoints,
        // default tunables.
        let plugin = WebhookPlugin::from_config_json("{}");
        let defaults = WebhookPluginConfig::default();
        assert!(plugin.config.endpoints.is_empty());
        assert_eq!(plugin.config.max_retries, defaults.max_retries);
        assert_eq!(plugin.config.retry_backoff_ms, defaults.retry_backoff_ms);
        assert_eq!(plugin.config.timeout_ms, defaults.timeout_ms);
        assert_eq!(plugin.config.buffer_size, defaults.buffer_size);
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn malformed_config_fails_closed() {
        // A present-but-unparseable config refuses the plugin rather
        // than silently degrading to defaults.
        let _ = WebhookPlugin::from_config_json("not json");
    }

    #[test]
    fn unknown_top_level_key_is_rejected() {
        // deny_unknown_fields: a typo'd / renamed top-level config key
        // is a hard parse error, not a silently-ignored field.
        let err =
            serde_json::from_str::<WebhookPluginConfig>(r#"{"max_retries": 2, "max_retires": 5}"#);
        assert!(err.is_err(), "unknown top-level key must be rejected");
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn unknown_key_fails_closed_via_factory() {
        // The same unknown-key parse error refuses the plugin at boot
        // through the fail_closed_config! factory path.
        let _ = WebhookPlugin::from_config_json(r#"{"timeout_ms": 1000, "tImeout_ms": 9}"#);
    }

    #[test]
    fn unknown_nested_endpoint_key_is_rejected() {
        // A typo inside a nested EndpointConfig is also rejected.
        let err = serde_json::from_str::<WebhookPluginConfig>(
            r#"{"endpoints": [{"url": "http://x", "evnts": ["all"]}]}"#,
        );
        assert!(err.is_err(), "unknown nested endpoint key must be rejected");
    }

    #[test]
    fn unknown_circuit_breaker_key_is_rejected() {
        // A typo inside the nested CircuitBreakerConfig is also rejected.
        let err = serde_json::from_str::<WebhookPluginConfig>(
            r#"{"circuit_breaker": {"open_duration_ms": 100, "open_durtaion_ms": 1}}"#,
        );
        assert!(err.is_err(), "unknown circuit_breaker key must be rejected");
    }
}
