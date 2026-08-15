# Webhook Notifications — `dev.mcpg.webhook`

> class `tool_gate` · `native` · package `mcpg-plugin-integration-webhook` · artifact `libmcpg_plugin_integration_webhook.so` · Apache-2.0

Pushes tool-call lifecycle events out of the gateway as HTTP POSTs, so external
systems — a chat channel, an on-call pager, a SIEM collector — learn when a tool
completed, failed, or ran slowly. It registers as a tool gate to observe every
call, but it always allows the request: notification never blocks or delays
dispatch. Events are handed to a bounded queue drained by a background sender
that retries with backoff, trips a per-endpoint circuit breaker on sustained
failure, and refuses to deliver to private network addresses. Reach for it when
you want operational visibility into tool traffic without standing up a log
pipeline.

## What it does
- Returns an allow decision on every request, before and after dispatch — it
  observes, it never gates.
- Queues each event onto a bounded channel drained by a dedicated background
  thread, so a slow receiver cannot add latency to a tool call.
- Emits one event per tool call — completed or error — plus a separate slow-response
  event when a call exceeds an endpoint's `slow_threshold_ms`.
- Fans each event out only to the endpoints whose `events` filter matches.
- Retries a failed delivery with exponentially growing backoff and ±20% jitter,
  capped at ten retries regardless of what the config asks for.
- Opens a per-endpoint circuit breaker after a run of server-side failures and
  recovers through half-open probes, so one broken receiver stops consuming
  retry budget.
- Resolves each endpoint host and refuses to send to a private, loopback, or
  link-local address unless the endpoint opts in; the validated address is pinned
  for the delivery and redirects are disabled.
- Drops events rather than blocking when the queue is full, and counts every drop.
- Declares the `network_outbound` capability, consumed by every delivery; the
  entry's `granted_capabilities` must list it or the plugin is refused at load.

## Configuration
Loaded from the flat top-level `plugins:` list. Every `tool_gate` entry joins the
gate chain and sees every tool call.

```yaml
plugins:
  - id: dev.mcpg.webhook
    class: tool_gate
    source: { path: ./plugins/libmcpg_plugin_integration_webhook.so }
    granted_capabilities: ["network_outbound"]
    config:
      max_retries: 3
      retry_backoff_ms: 1000
      timeout_ms: 5000
      buffer_size: 1024
      circuit_breaker:
        consecutive_5xx_threshold: 5
        open_duration_ms: 30000
        half_open_probe_count: 1
      endpoints:
        - url: https://hooks.example.com/mcpg
          events: ["error", "slow_response"]
          slow_threshold_ms: 2000
          headers:
            Authorization: Bearer ${env.HOOK_TOKEN}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `endpoints` | endpoint[] | `[]` | Webhook receivers; with none configured the plugin allows every call and sends nothing. |
| `max_retries` | u32 | `3` | Retry attempts after the first failed send. Values above 10 are clamped to 10 with a warning. |
| `retry_backoff_ms` | u64 | `1000` | Base backoff; doubles each attempt and carries ±20% jitter. |
| `timeout_ms` | u64 | `5000` | Per-request timeout on a delivery. |
| `buffer_size` | usize | `1024` | Depth of the bounded event queue; a full queue drops the event. |
| `circuit_breaker.consecutive_5xx_threshold` | u32 | `5` | Consecutive failures before the breaker opens for an endpoint. |
| `circuit_breaker.open_duration_ms` | u64 | `30000` | How long the breaker stays open before admitting a probe. |
| `circuit_breaker.half_open_probe_count` | u32 | `1` | Deliveries admitted while half-open; one failure re-opens the breaker. |

Each entry under `endpoints`:

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | — (required) | Receiver URL. |
| `events` | string[] | `[]` | Event filter; see the token table below. Empty matches every event. |
| `slow_threshold_ms` | u64? | `null` | Emit a slow-response event when a call exceeds this duration. Unset disables it for this endpoint. |
| `headers` | map<string,string> | `{}` | Static headers added to every POST from this endpoint. |
| `allow_private_backends` | bool | `false` | Permit delivery to private, loopback, or link-local addresses. |

Unknown fields are rejected. An empty or absent `config:` block yields the
defaults above; a *present but malformed* block fails the plugin's load rather
than silently running with defaults.

## Operations
Each delivery is a JSON POST whose `event` field names the kind. Note that the
`events` filter on an endpoint matches a shorter token than the one that appears
in the payload — the two vocabularies are not the same:

| Filter token in `events` | Payload `event` value | Fires when |
|---|---|---|
| `completed` | `tool_call_completed` | A tool call returned without an error result. |
| `error` | `tool_call_error` | The tool result carries `isError: true`. |
| `slow_response` | `slow_response` | The call exceeded this endpoint's `slow_threshold_ms`. |
| `all` | — | Matches every event kind. |

A completed event carries `tool_name`, `request_id`, `duration_ms`,
`identity_kind`, and `subject_id`. An error event carries `tool_name`,
`request_id`, `error_message` (the first text content block of the result), and
`identity_kind`. A slow-response event carries `tool_name`, `request_id`,
`duration_ms`, and `threshold_ms`.

## Security
Deliveries go through an SSRF guard. Before the first send the endpoint host is
resolved and checked: unless that endpoint sets `allow_private_backends: true`,
an address that is private, loopback, or link-local is rejected and the event is
dropped. The address that passed is then pinned into the delivery client and
redirects are disabled, so neither a DNS rebind between resolution and connect
nor a 30x response can steer the POST at an internal host — the remote address of
each response is re-checked for the same reason. A URL that fails to parse is
dropped without being echoed into logs, since it may carry userinfo.

Endpoint URLs and headers are substituted by the gateway at config load, so write
`${env.VAR}` for a receiver token rather than a literal.

On shutdown the plugin allows a one-second drain window for queued events. Events
still in flight past that budget are lost — this is a notification path, not an
audit trail. Use an `audit_sink` plugin where delivery must be guaranteed.

## Observability
- `mcpg_webhook_dropped_events_total` — events discarded because the queue was full.
- `mcpg_webhook_request_duration_ms{endpoint}` — per-attempt delivery latency.
- `mcpg_webhook_backoff_applied_ms{endpoint}` — the backoff actually slept between attempts.
- `mcpg_webhook_circuit_state{endpoint,state}` — current breaker state, one of
  `closed`, `open`, `half_open`.
- `mcpg_webhook_circuit_short_circuited_total{endpoint}` — deliveries skipped by an open breaker.
- `mcpg_dns_rebinding_blocked_total{host}` — deliveries blocked by the SSRF guard.

Each delivery runs inside a `webhook_deliver` span carrying the endpoint, so
retries and outcomes correlate back to the originating call.

## Build
`cdylib-export` is enabled by default, so the plain build already produces the
loadable artifact. Disable the default features when linking this crate as an
rlib path dependency alongside other plugins, so the build does not emit two
`mcpg_plugin_register` exports.

```bash
cargo build -p mcpg-plugin-integration-webhook --features cdylib-export --release   # → target/release/libmcpg_plugin_integration_webhook.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes and the ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- The full plugin catalog: <https://mcpg.dev/docs/plugins/plugin-catalogue>
- Full gateway config schema: <https://mcpg.dev/docs/reference/configuration>
