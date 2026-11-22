# agentd session swap

`agentd_session_swap` lets one proxy, shared by many sandboxes, swap
per-session placeholders for real credential values only for the session that
owns them. It serves [agentd](https://github.com/Elmanuel1/agentd)'s `cloud`
sandboxes, whose `environment_variable` credentials hold signed `agentd-ph-`
placeholders in place of values. It is the policy gate for the requests it
sees, so it needs no `allowlist` beside it. A complete config is in
[`iron-proxy.yaml`](iron-proxy.yaml).

```yaml
- name: agentd_session_swap
  config:
    agentd_url: "https://agentd.internal"  # agentd's Managed Agents API
    store: aws_sm                          # aws_sm or aws_ssm
    secret_prefix: "agentd"                # agentd's AGENTD_SECRETS_PREFIX
    region: "us-west-2"
    ttl: "5m"                              # how long a value is kept; default 5m
```

| Variable | Meaning |
|---|---|
| `AGENTD_PLACEHOLDER_KEYS` | agentd's placeholder key ring, `<id>:<hex>,…`. Any key verifies what it signed |
| `AGENTD_RUNTIME_KEYS` | agentd's runtime keys; the first reads environments |

Each request goes through these steps:

1. **Caller.** A sandbox sets `HTTPS_PROXY` and `HTTP_PROXY` to
   `http://<session id>:<work token>@<proxy>:<tunnel port>`, so its client
   sends `Proxy-Authorization: Basic` on `CONNECT` and on plain-HTTP
   requests. The pair is checked with `GET /v1/sessions/{id}` under that
   token, and the answer, a refusal included, is kept 60 s per digest of the
   pair. A missing or refused pair is `407`. The identity is bound to the
   tunnel: requests inside it are not checked again, and a
   `Proxy-Authorization` they carry is ignored and stripped before
   forwarding.
2. **Egress.** The session's environment is read with the runtime key from
   `GET /v1/environments/{id}` and kept 60 s. `limited` networking reaches
   only its `allowed_hosts` (globs as in the allowlist), plus the package
   registries when `allow_package_managers` is set; `unrestricted` reaches
   every host `proxy.upstream_deny_cidrs` allows. Any other host is `403`,
   checked on the `CONNECT` target and on each inner request's `Host`.
3. **Swap.** Only inside TLS, each placeholder in a header, or in a body of
   known length up to 1 MiB, is verified. A larger body is streamed
   untouched. One whose MAC fails, whose session
   is not the caller's, or whose credential does not allow the host or the
   location is sent unchanged. Otherwise the credential's sealed secret,
   `<secret_prefix>/<workspace>/<vault>/<credential>`, is read through the
   `aws_sm` or `aws_ssm` source and kept for `ttl`, so a rotated value is
   used once the `ttl` passes. Its `networking` and `injection_location`
   decide where the value goes. A value that cannot be read fails the
   request with `502`.

Each swap logs the credential id and a keyed fingerprint of the value at
`INFO`, never the value. `agentd_url` must be `https`: the work token and
the runtime key travel on it. A failure to reach agentd fails the request
closed: `502` inside a tunnel, `403` on `CONNECT`.

Set `proxy.upstream_deny_cidrs` to every range a sandbox must not reach, as
the example does: unspecified, loopback, link-local (which holds the metadata
endpoints), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
`100.64.0.0/10`, `fc00::/7`). They are checked after DNS resolution.

With `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`)
set, the transform exports three counters over OTLP every 60 s, by the
standard `OTEL_*` variables. Export starts with the transform, so a proxy
without it exports no metrics, and a stop drops what was counted since the
last send:

| Metric | Meaning | Alert when |
|---|---|---|
| `proxy_swaps` | placeholders replaced with a value | (traffic) |
| `proxy_refusals` | requests refused, by `reason`: `proxy_auth`, `egress_policy`, `caller_unavailable`, `policy_unavailable` | `caller_unavailable` or `policy_unavailable` above 0 |
| `proxy_read_failures` | credential values that could not be read | above 0 |
