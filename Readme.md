# Novaflow

Novaflow is a virtual server-based **Web Application Firewall (WAF)** powered by
asynchronous processing on Tokio. Version 0.2 replaces the original flat
regex-matching engine with a **semantic anomaly-scoring detection engine** —
the same detection philosophy used by the most effective open-source WAFs
(OWASP CRS / Coraza anomaly scoring, SafeLine semantic analysis, open-appsec
contextual analysis).

## Why the engine was rewritten

The v1 algorithm matched raw regexes against the raw request. That class of
WAF is trivially evadable and noisy. Concretely, v1:

| v1 weakness | v2 fix |
|---|---|
| Regex compiled **on every request** (per rule, per request!) | All custom rules compiled **once at startup** |
| No decoding — `%3Cscript%3E`, double encoding, HTML entities, null bytes sail through | **Normalization pipeline**: repeated percent-decode, entity decode, control-char cleanup, SQL comment stripping |
| Query string never inspected (path only) | Path + **every query `key=value` pair** + header values + body |
| One rule = one flat regex → instant block, huge FP surface | **Anomaly scoring**: contextual signals score 2–5, request blocked when the sum reaches a configurable threshold |
| Keywords matched without context (`select` in prose = FP) | **Contextual heuristics**: keywords only score high with quotes/comments/operators; UNION+SELECT must be adjacent; query assignments (`?q=`) are not treated as SQL operators |
| Domain routing read `uri.host()` — empty for normal requests | Host taken from the **Host header**, case-insensitive, `.example.com` wildcard support |
| Virtual-server match by config order | **Longest-prefix match** |
| New `reqwest::Client` per request (TLS handshake each time) | **Shared connection-pooled client** |
| Hop-by-hop headers forwarded upstream | Stripped per RFC 7230; `X-Forwarded-For` appended |
| HTTP/2 only (curl/HTTP1.1 clients failed) | **Auto-detected HTTP/1.1 + HTTP/2** per connection |

## Detection pipeline

```
request ─▶ surfaces (path, query pairs, headers, body)
        ─▶ normalize (decode ×4, entities, control chars, comment strip)
        ─▶ semantic detectors: SQLi · XSS · path traversal · command injection · RFI
        ─▶ custom regex rules (precompiled)
        ─▶ anomaly score = Σ detection scores
        ─▶ score ≥ threshold ? 403 : forward upstream
```

Every detector family, keyword list, score and the threshold is configured
in **`policy.yaml`** — nothing is hardcoded in the binary. See the heavily
commented `policy.yaml` for every knob.

## Operating modes

```yaml
detection:
  mode: block            # or: detect (log-only learning mode)
  anomaly_threshold: 5   # CRS-style: sum of scores needed to block
```

`detect` mode lets you measure false positives against real traffic before
enforcing — the standard CRS rollout practice.

## Commands

```bash
Usage: novaflow [OPTIONS]

Options:
  -c, --config <CONFIG>  [default: config.yaml]
  -p, --policy <POLICY>  [default: policy.yaml]
  -h, --help             Print help
  -V, --version          Print version
```

## Configuration

Server config (unchanged shape) — see `example/config.yaml`:

```yaml
listen_address: "0.0.0.0"
listen_port: 9000
ssl:
  enabled: true
  ca_path: "example/sample.pem"
  key_path: "example/sample.rsa"
domain_server:
  enabled: true
  config:
    - name: domain_1
      domain_name: testserver.com        # or ".example.com" wildcard
      remote_address: "http://1.1.1.1"
virtual_server:
  enabled: true
  config:
    - name: "Backend1"
      path: /backend1                    # longest-prefix wins
      remote_address: "https://www.example.com/"
```

Policy (`policy.yaml`) — the full detection algorithm:

- `detection:` mode, anomaly threshold, body limit
- `rules.sqli:` keyword list, probing functions, stacked-query starters, 7 tunable scores
- `rules.xss:` dangerous tags, event tags, JS primitives, 5 tunable scores
- `rules.path_traversal:` sequences, sensitive files, PHP wrappers, scores
- `rules.command_injection:` shell commands, substitution markers, scores
- `rules.rfi:` include-ish parameter names, remote schemes, score
- `custom_rules:` your own regexes (run against the **normalized** request),
  each with its own score and target surfaces (`uri`/`header`/`body`).
  The v1 key `policy_block` is still accepted.

## Run locally

```bash
novaflow -c ./example/config.yaml -p ./example/policy.yaml
```

## Admin API

NovaFlow exposes management endpoints under `/novaflow/` that are routed
**before** WAF inspection so health checks and the dashboard remain reachable
even when traffic would otherwise be blocked.

| Endpoint | Method | Description |
|---|---|---|
| `/novaflow_healthz` | GET | Backward-compatible simple health check |
| `/novaflow/api/health` | GET | Detailed health: engine status + upstream probes for every virtual/domain server |
| `/novaflow/api/config` | GET | Current `ServerConfig` (listen address, SSL, proxies) |
| `/novaflow/api/policy` | GET | Current `PolicyConfig` (detection + rules) |
| `/novaflow/api/policy` | POST | Validate YAML, persist to disk, and reload the engine live |

All API responses include CORS headers so the dashboard dev server can call
them cross-origin.

## Documentation

Full documentation lives in `docs/` and is built with [Mintlify](https://mintlify.com/).

```bash
cd docs
npx mintlify dev
```

See `docs/README.md` for details.

## SvelteForge Admin Dashboard

A management UI based on [SvelteForge Admin](https://github.com/ColorlibHQ/svelteforge-admin)
lives in `dashboard/`. It runs as a separate Node service and talks to the
Rust admin API.

### Start the dashboard

```bash
cd dashboard
npx pnpm@10.28.1 install
npx pnpm@10.28.1 dev
```

The dashboard defaults to `http://localhost:5173` and expects the NovaFlow API
at `http://localhost:9000`. Override with `NOVAFLOW_API_URL` in `dashboard/.env`.

### Dashboard pages

- **NovaFlow Health** — engine status and per-upstream probe results
- **NovaFlow Rules** — view and edit `policy.yaml`, then reload the engine
- **NovaFlow Config** — read-only view of server/proxy configuration

### Production build

```bash
cd dashboard
npx pnpm@10.28.1 build
node build
```

The template uses `@sveltejs/adapter-node`, so `node build` starts the
standalone dashboard server.

## Logging

All logs are emitted as structured JSON. Every proxied request produces an `access` entry with `request_id`, `remote_addr`, `method`, `uri`, `host`, `status`, `anomaly_score`, `action` (`allowed`/`detected`/`blocked`), and `rules`.

```yaml
logging:
  mode: "stdout"   # or "file" / "syslog"
  file_path: "/tmp/"
  file_name: "novaflow.log"
```

- `stdout` — blocking JSON lines to stdout
- `file` — daily rolling file (`<file_path>/<file_name>.YYYY-MM-DD`)
- `syslog` — local syslog daemon via `/dev/log` with tag `novaflow`

## Tests

```bash
cargo test
```

24 unit tests cover the normalization pipeline, every detector family
(true positives **and** false-positive guards on benign prose), anomaly
accumulation across surfaces, detect-mode, custom rules and config respect.

## Roadmap

- Rate limiting and IP reputation
- Body inspection for JSON/XML schemas
- Multiple policy files with per-virtual-server policies
