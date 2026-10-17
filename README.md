# Webhook Notifications — `dev.mcpg.webhook`

> class `tool_gate` · `native` · package `mcpg-plugin-integration-webhook` · artifact `libmcpg_plugin_integration_webhook.so` · Apache-2.0

Pushes tool-call lifecycle events out of the gateway as HTTP POSTs, so external
systems — a chat channel, an on-call pager, a SIEM collector — learn when a tool
completed, failed, or ran slowly. It registers as a tool gate to observe every
call, but it always allows the request: notification never blocks or delays
dispatch. Each delivery follows [Standard Webhooks](https://www.standardwebhooks.com/):
it carries a `webhook-id`, a `webhook-timestamp` and, for an endpoint with
signing secrets, a `webhook-signature` any Standard Webhooks library can check.
Events are handed to a bounded queue drained by a background sender
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
- Sends the Standard Webhooks headers on every delivery attempt, under one
  `webhook-id` per event, and signs each attempt with the endpoint's
  `signing_secrets` when it sets them.
- Treats only a `2xx` answer as delivered. A `410 Gone` stops all delivery to
  that endpoint; a `413` drops the event without a retry.
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
          signing_secrets: ["${secret.HOOK_WHSEC}"]
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
| `circuit_breaker.half_open_probe_count` | u32 | `1` | Deliveries admitted while half-open; one failure re-opens the breaker. Probes that end without a verdict, such as a `4xx` after its retries, are admitted again after `open_duration_ms`. |

Each entry under `endpoints`:

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | — (required) | Receiver URL. |
| `events` | string[] | `[]` | Event filter; see the token table below. Empty matches every event. |
| `slow_threshold_ms` | u64? | `null` | Emit a slow-response event when a call exceeds this duration. Unset disables it for this endpoint. |
| `headers` | map<string,string> | `{}` | Static headers added to every POST from this endpoint. A `webhook-id`, `webhook-timestamp` or `webhook-signature` entry, in any letter case, fails the load. |
| `signing_secrets` | string[] | `[]` | Standard Webhooks secrets, `whsec_` and the base64 of a 24 to 64 byte key. The first is the current one; list the previous one after it during a rotation. Surrounding whitespace is trimmed. Empty: the endpoint's deliveries are not signed, and the load logs a warning that names the endpoint by its index. |
| `allow_private_backends` | bool | `false` | Permit delivery to private, loopback, or link-local addresses. |

Unknown fields are rejected. An empty or absent `config:` block yields the
defaults above; a *present but malformed* block fails the plugin's load rather
than silently running with defaults. A malformed signing secret fails the load
too, and the error names its position and the rule it breaks, never the
value.

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

| Answer | What the plugin does |
|---|---|
| `2xx` | Delivered. |
| `410 Gone` | Stops sending to that endpoint until the configuration reloads or the gateway restarts, logs one error that names the endpoint by its index, and counts `mcpg_webhook_gone_total`. |
| `413` | Drops the event for that endpoint without a retry: the same bytes are always too large. |
| `3xx` | A failure: redirects are not followed. Retried as below. |
| Any other answer, a timeout, a network error | Retried with backoff up to `max_retries`. `5xx` and network errors count toward the circuit breaker. |

A `2xx`, a `410` and a `413` each show that the receiver is up, so each one
closes the endpoint's circuit breaker.

## Signing
Every delivery follows [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md):

| Header | Value |
|---|---|
| `webhook-id` | `msg_` and a UUIDv7, one per event. It is the same on every endpoint and every retry of that event, so a receiver deduplicates on it. |
| `webhook-timestamp` | Unix seconds of this attempt. |
| `webhook-signature` | `v1,` and the base64 HMAC-SHA256 of `{webhook-id}.{webhook-timestamp}.{body}`, one space-separated entry per signing secret. Sent only when the endpoint has `signing_secrets`. |

Each retry carries a new timestamp and a new signature. To rotate a secret, list
the new one first and the old one after it: every delivery is then signed with
both, so a receiver that holds either accepts it. Remove the old one once the
receiver has the new one.

A receiver checks a delivery with any Standard Webhooks library, over the raw
body bytes as they arrived. In Python, with the `standardwebhooks` package:

```python
import os
from standardwebhooks.webhooks import Webhook

Webhook(os.environ["HOOK_WHSEC"]).verify(raw_body, request.headers)
```

In Rust, with `mcpg-standard-webhooks`:

```rust
use mcpg_standard_webhooks::{Verifier, WhsecSecret};

let verifier = Verifier::new(vec![WhsecSecret::parse(&secret)?])?;
verifier.verify_headers(&headers, &raw_body, now_unix_secs)?;
```

Both refuse a timestamp more than five minutes from the receiver's clock.

## Security
Deliveries go through an SSRF guard. Before the first send the endpoint host is
resolved and checked: unless that endpoint sets `allow_private_backends: true`,
an address that is private, loopback, or link-local is rejected and the event is
dropped. The address that passed is then pinned into the delivery client and
redirects are disabled, so neither a DNS rebind between resolution and connect
nor a 30x response can steer the POST at an internal host — the remote address of
each response is re-checked for the same reason. A URL that fails to parse is
dropped without being echoed into logs, since it may carry userinfo.

Endpoint URLs, headers and signing secrets are substituted by the gateway at
config load, so write `${env.VAR}` or `${secret.NAME}` for a receiver token or a
signing secret rather than a literal.

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
- `mcpg_webhook_gone_total{endpoint_index}` — `410 Gone` answers;
  `endpoint_index` is the endpoint's index in `endpoints`, not its URL.
- `mcpg_dns_rebinding_blocked_total{host}` — deliveries blocked by the SSRF guard.

Each delivery runs inside a `webhook_deliver` span carrying the endpoint's
index as `endpoint_index`, so retries and outcomes correlate back to the
originating call. The `410` error, the `413` warning and the load-time warning
name the endpoint by that index only.

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
