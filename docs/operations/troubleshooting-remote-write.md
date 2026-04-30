# Troubleshooting Remote Write

Entries are ordered by likelihood — start at the top. Each entry follows the same structure: symptom, what to check, how to fix, and which self-metric or audit event confirms the issue.

---

## 1. No samples reaching the receiver at all

**Symptom.** The receiver shows no `signet_*` series at all for the expected instance. There is no `up` metric for the Signet stream. The receiver's ingestion count does not increase when Signet is running.

**Check: `signet_remote_write_samples_sent_total` on Signet's `/metrics`.**

- **Counter is zero and not incrementing.** Remote write is either not enabled or the sender goroutine failed to start. Verify `cfg.RemoteWrite.Enabled: true` in `signet.yaml`. Check Signet's startup logs for `init remote write sender` error messages — configuration validation errors (invalid endpoint URL, missing cert files) will surface here and prevent the sender from starting. If the counter exists but is zero after several scrape intervals, the sender is running but has not produced any samples yet; wait for the first gather cycle to complete.

- **Counter is incrementing.** Samples are leaving Signet successfully. The failure is between Signet and the receiver. Check the network path (firewall rules, routing, DNS resolution of the receiver hostname from the Signet host). Check the receiver's ingestion logs and health endpoints. Verify the receiver endpoint URL in `signet.yaml` is reachable from the Signet host: `curl -sv https://<receiver>/api/v1/push` from a shell running as the `signet` user.

**Related metrics:** `signet_remote_write_samples_sent_total`, `signet_remote_write_last_success_timestamp`

---

## 2. 4xx response failures (config error, fail-fast)

**Symptom.** `signet_remote_write_failures_total{reason="4xx"}` incrementing. `signet_remote_write_samples_dropped_total{reason="fatal_response"}` also incrementing. Samples are leaving Signet but the receiver is permanently rejecting them.

**Common causes:**

- **401 / 403 auth rejection.** Bearer token wrong or expired, mTLS client cert not trusted by the receiver, or basic auth credentials incorrect. Check the Signet logs for the response body excerpt (256 bytes, enough to identify the receiver's rejection message).
- **413 payload too large.** Signet's default batch size exceeds the receiver's ingestion limit. Reduce `queue.max_samples_per_send` in `signet.yaml`.
- **422 label validation failure.** A label value exceeds the receiver's length limit (Mimir default: 1,024 bytes), or the receiver has hit a per-series or per-tenant label cardinality limit. Check the response body for the specific label name the receiver rejected.
- **Mimir multi-tenancy: missing or wrong tenant header.** If the receiver is a multi-tenant Mimir cluster, the `X-Scope-OrgID` header must match a valid tenant. Set `remote_write.headers."X-Scope-OrgID"` in `signet.yaml`.

**How to fix.** Address the receiver-side complaint. Signet does not retry 4xx responses — they are treated as fatal configuration errors. Samples dropped with `reason="fatal_response"` are gone. Fix the configuration and either restart Signet or send `SIGHUP` to reload if the fix involves a reloadable config field.

**Check:** Signet's logs at WARN level will contain a truncated excerpt of the response body from the receiver. This is almost always sufficient to identify the cause without accessing the receiver directly.

**Related metrics:** `signet_remote_write_failures_total{reason="4xx"}`, `signet_remote_write_samples_dropped_total{reason="fatal_response"}`

---

## 3. 5xx response failures (receiver overloaded or down)

**Symptom.** `signet_remote_write_failures_total{reason="5xx"}` incrementing. Queue size growing. After approximately 5 minutes of consecutive failures, the audit log emits `remote_write.endpoint_unreachable`.

**Common causes.** Receiver is down (service restart, maintenance, node failure). Receiver is overloaded and returning 503 (ingestion rate limit exceeded). Receiver disk or IOPS is exhausted (common on under-provisioned Mimir ingesters).

**Check.**

- Receiver-side health endpoint (Mimir: `/ready`, Prometheus: `/-/healthy`).
- Mimir distributor ingestion rate: `sum(rate(cortex_distributor_received_samples_total[1m]))` — compare against the configured `ingestion_rate` limit.
- Receiver disk IOPS and write latency if available.

**How to fix.** Scale the receiver to handle the ingestion rate, or reduce Signet's contribution by increasing `interval` (trades metric freshness for headroom) or applying cardinality reduction.

**Recovery.** When the receiver recovers and Signet's next send attempt succeeds, the audit log emits `remote_write.recovered` and `signet_remote_write_last_success_timestamp` resumes advancing. `signet_remote_write_failures_total` stops incrementing. No operator action is required for recovery — Signet retries automatically with exponential backoff.

**Related metrics:** `signet_remote_write_failures_total{reason="5xx"}`, `signet_remote_write_queue_size`
**Related audit events:** `remote_write.endpoint_unreachable`, `remote_write.recovered`

---

## 4. Network errors (timeout, DNS, connection refused)

**Symptom.** `signet_remote_write_failures_total{reason="network"}` or `{reason="timeout"}` incrementing. Signet logs show `StatusCode: 0` — the request never received a response. Unlike 5xx failures where the receiver answered with an error, network failures mean the connection was never established or timed out before completion.

**Common causes:**

- **DNS resolution failure under systemd sandboxing.** A known issue from v0.3.1 packaging: `ProtectSystem=strict` combined with aggressive `RestrictAddressFamilies` settings can break NSS lookups. The systemd unit ships with `AF_NETLINK` in `RestrictAddressFamilies` and `ReadOnlyPaths=/etc/resolv.conf` to address this. If you have customized the unit, verify these are present. Test: `getent hosts <receiver-hostname>` run as the `signet` user to confirm DNS resolution works in the service's security context.
- **Firewall rules.** Egress from the Signet host to the receiver on the remote write port (typically 443 or 9090) may be blocked. Test with `curl -v https://<receiver>/api/v1/push` from the Signet host as the `signet` user.
- **Load balancer idle connection timeout.** If the receiver is behind a load balancer with an idle connection timeout shorter than Signet's `IdleConnTimeout` (90 seconds by default), the load balancer will close connections that Signet considers open. This produces `connection reset by peer` or `EOF` errors. Align the load balancer's idle timeout to be longer than Signet's, or reduce Signet's `IdleConnTimeout` below the LB timeout.
- **TLS handshake timeout.** The remote write client has a default handshake timeout. If the receiver's TLS stack is slow (e.g., large certificate chain, slow HSM), increase `remote_write.tls_handshake_timeout` in `signet.yaml`.

**Check.** From the Signet host, as the `signet` user:

```sh
# DNS resolution
getent hosts <receiver-hostname>

# L4 reachability and TLS handshake
curl -v --cert /etc/signet/tls/client.pem \
        --key  /etc/signet/tls/client-key.pem \
        --cacert /etc/signet/tls/ca.pem \
        https://<receiver-hostname>:<port>/api/v1/push
```

**Related metrics:** `signet_remote_write_failures_total{reason="network"}`, `signet_remote_write_failures_total{reason="timeout"}`

---

## 5. Queue full drops

**Symptom.** `signet_remote_write_samples_dropped_total{reason="queue_full"}` incrementing. `signet_remote_write_queue_size` is at or near `queue.max_samples`. The queue is filling faster than it drains.

**Cause.** Receiver throughput is below Signet's production rate. Either the receiver is slow (check for accompanying 5xx failures) or Signet's gather cycle is producing more samples per interval than the queue can absorb. This is distinct from receiver failure — the receiver may be healthy but simply slower than Signet is generating.

**Fix options, in order of preference:**

1. **Apply cardinality reduction.** Drop `signet_port_open` if port-presence visibility is not part of your use case — this removes O(hosts × ports) series and is the highest-leverage reduction available. See `examples/alloy/cardinality-conscious.alloy` for the relabeling pattern; transpose it to Signet config-level filtering for native remote write.

2. **Increase `queue.max_samples`.** Larger queue absorbs burst production and smooths delivery. Memory cost is proportional: each queued sample is approximately 100 bytes; 100,000 samples ≈ 10 MB of in-process memory.

3. **Increase `interval`.** A longer remote write interval reduces send frequency. This trades metric freshness at the receiver for queue headroom.

4. **Scale the receiver.** If the receiver is the bottleneck and cardinality reduction is not acceptable, additional receiver capacity is the right answer.

**Related metrics:** `signet_remote_write_samples_dropped_total{reason="queue_full"}`, `signet_remote_write_queue_size`

---

## 6. Conversion errors

**Symptom.** `signet_remote_write_samples_dropped_total{reason="conversion_error"}` incrementing. Most other metrics are reaching the receiver normally, but one or more metric families are missing.

**Cause.** Almost always an external label collision with a metric-native label. If an external label key (e.g., `subnet`) matches a label that Signet already emits on a metric family, the converter returns a `LabelCollisionError` for that family and skips it. Other metric families that do not have the colliding label continue to be converted and sent normally.

**Check.** Look for WARN-level log entries containing `LabelCollisionError`. The entry names the metric family, the colliding label key, the value from the external labels block, and the value from the metric family. Example:

```
level=warn msg="label collision in metric family" metric=signet_host_up label=subnet external_value=10.0.0.0/16 metric_value=10.0.0.0/16 action=drop_family
```

**Fix.** Either rename the external label (e.g., change `subnet` to `scan_subnet` or `network_zone`) so it no longer collides, or remove it from `external_labels` — the metric already carries the label organically.

**Related metrics:** `signet_remote_write_samples_dropped_total{reason="conversion_error"}`

---

## 7. Bearer token auth failures after rotation

**Symptom.** A bearer token was rotated on disk. Signet continues sending the old token and auth failures increment (`signet_remote_write_failures_total{reason="4xx"}` with 401 responses in the logs).

**Cause.** Signet did not re-read the token file. The token file is read at startup and on SIGHUP. If neither occurred after the rotation, Signet holds the old token in memory.

**Check.**

```sh
# Verify file ownership and permissions
stat /etc/signet/token

# Verify Signet's process user can read it
sudo -u signet cat /etc/signet/token

# Check for config_reloaded in the audit log
grep remote_write.config_reloaded /var/log/signet/audit.log | tail -5
```

**Fix.**

1. Ensure the token file is owned by `signet:signet` with mode `0600` — if the `signet` user cannot read it, the reload will silently fall back to the previous token.
2. Send SIGHUP after every token rotation: `systemctl reload signet-exporter`. The audit log emits `remote_write.config_reloaded` on success.

**Related audit events:** `remote_write.config_reloaded`
**Related metrics:** `signet_remote_write_failures_total{reason="4xx"}`

---

## 8. mTLS handshake failures

**Symptom.** `signet_remote_write_failures_total{reason="network"}` incrementing. Signet logs show TLS handshake errors: `tls: certificate required`, `tls: unknown certificate authority`, `tls: protocol version not supported`, or similar. Samples never reach the receiver.

**Common causes:**

- **Client cert expired.** The certificate at `auth.client_cert_file` has passed its `Not After` date. The receiver will reject it during the handshake.
- **CA mismatch.** The CA file at `auth.ca_cert_file` does not include the issuer of the receiver's server certificate. Signet's TLS client will refuse to complete the handshake because it cannot verify the server.
- **Receiver CA does not trust Signet's client cert.** The receiver's client CA bundle does not include the issuer of the certificate at `auth.client_cert_file`. The receiver will reject the handshake.
- **TLS version mismatch.** Signet enforces TLS 1.2 as a minimum on the remote write client. If the receiver is configured for TLS 1.0 or 1.1, the handshake will fail.

**Check.**

```sh
# Test the full mTLS handshake from the Signet host
openssl s_client \
  -connect <receiver-host>:<port> \
  -cert /etc/signet/tls/client.pem \
  -key  /etc/signet/tls/client-key.pem \
  -CAfile /etc/signet/tls/ca.pem \
  -tls1_2

# Check client cert expiry
openssl x509 -in /etc/signet/tls/client.pem -noout -dates

# Check which CA signed the receiver's server cert
openssl s_client -connect <receiver-host>:<port> -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer
```

**Fix.** Rotate expired certificates. Fix the CA bundle so Signet trusts the receiver's server cert issuer and the receiver trusts Signet's client cert issuer. Upgrade the receiver's TLS configuration to TLS 1.2 or later if it is configured for an older version.

After rotating certs, send `SIGHUP` (`systemctl reload signet-exporter`) — Signet re-reads the cert, key, and CA files without restarting.

**Related metrics:** `signet_remote_write_failures_total{reason="network"}`
