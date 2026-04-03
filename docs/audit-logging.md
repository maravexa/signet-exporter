# Audit Logging

signet-exporter emits structured audit records for security-relevant network events.
Records can be written in JSON (default) or CEF (Common Event Format) for SIEM integration.

## Configuration

```yaml
audit:
  enabled: true       # set to false to disable all audit output
  format: "json"      # "json" (default) or "cef"
  output: "file"      # "stderr" | "stdout" | "file"
  path: "/var/log/signet/audit.log"  # used when output is "file"
```

### Format

| Value | Description |
|-------|-------------|
| `json` | One JSON object per line. Default. Human-readable; easy to parse with `jq`. |
| `cef` | Common Event Format. One line per event. Compatible with Splunk, QRadar, ArcSight, and other SIEM platforms. |

### Output destination

| Value | Destination |
|-------|-------------|
| `stderr` | Standard error (default when `output` is empty) |
| `stdout` | Standard output |
| `file` | Append to the file at `path`. Parent directory must exist. |

The exporter does **not** rotate log files. Use an external tool (see Log Rotation below).

## Log Rotation

### logrotate

```
/var/log/signet/audit.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

`copytruncate` avoids sending a signal — the exporter holds the file open and continues
writing after truncation with no restart required.

### systemd journal (alternative)

Set `output: stderr` and let journald collect the records:

```yaml
audit:
  enabled: true
  format: "json"
  output: "stderr"
```

Retrieve with:

```
journalctl -u signet-exporter -o json | jq 'select(.event_type != null)'
```

## Event Reference

### JSON format fields

Every JSON audit record contains:

| Field | Type | Description |
|-------|------|-------------|
| `time` | RFC 3339 | Timestamp of the event |
| `level` | string | `INFO` or `WARN` |
| `msg` | string | Always `"audit"` |
| `event_type` | string | One of the event types below |
| _(event fields)_ | varies | Event-specific fields |

### CEF format

CEF lines follow the structure:

```
CEF:0|Signet|signet-exporter|<version>|<id>|<name>|<severity>|<extensions>
```

Severity is a numeric value 0–10 per the CEF specification:
- 0–3: Low
- 4–6: Medium
- 7–8: High
- 9–10: Very High

### Event types

| `event_type` | CEF ID | CEF Severity | Description |
|---|---|---|---|
| `new_host_discovered` | 100 | 3 | A host was seen for the first time |
| `host_disappeared` | 150 | 3 | A previously seen host became stale |
| `mac_ip_change` | 200 | 7 | An IP address changed its MAC binding |
| `unauthorized_device` | 300 | 9 | A host's MAC is not on the allowlist |
| `duplicate_ip_detected` | 400 | 7 | Multiple MACs are claiming the same IP |
| `scan_completed` | 500 | 0 | A single scanner pass finished |
| `scan_cycle_complete` | 550 | 0 | All scanners completed for a subnet |
| `scan_error` | 600 | 5 | A scanner encountered an error |
| `config_reloaded` | 700 | 2 | Configuration was hot-reloaded |
| `cert_reloaded` | 800 | 2/7 | TLS certificate reload succeeded/failed |

### Event field reference

#### `new_host_discovered`

| Field | JSON key | CEF ext key |
|-------|----------|-------------|
| IP address | `ip` | `src` |
| Subnet CIDR | `subnet` | `subnet` |
| MAC address | `mac` | `mac` |
| OUI vendor | `vendor` | `vendor` |
| Hostname | `hostname` | `hostname` |

#### `mac_ip_change`

| Field | JSON key | CEF ext key |
|-------|----------|-------------|
| IP address | `ip` | `src` |
| Subnet CIDR | `subnet` | `subnet` |
| Previous MAC | `old_mac` | `oldMac` |
| New MAC | `new_mac` | `newMac` |
| Previous vendor | `old_vendor` | `oldVendor` |
| New vendor | `new_vendor` | `newVendor` |

#### `unauthorized_device`

| Field | JSON key | CEF ext key |
|-------|----------|-------------|
| IP address | `ip` | `src` |
| Subnet CIDR | `subnet` | `subnet` |
| MAC address | `mac` | `mac` |
| OUI vendor | `vendor` | `vendor` |

#### `scan_error`

| Field | JSON key | CEF ext key |
|-------|----------|-------------|
| Subnet CIDR | `subnet` | `subnet` |
| Scanner name | `scanner` | `scanner` |
| Error message | `error` | `msg` |

## SIEM Integration

### Splunk

Add a file input monitor in `inputs.conf`:

```ini
[monitor:///var/log/signet/audit.log]
sourcetype = signet:audit:json
index = network_security
```

For CEF format, set `sourcetype = cef`.

### Elastic / OpenSearch

Use Filebeat with the CEF decoder:

```yaml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/signet/audit.log
    processors:
      - decode_cef:
          field: message
          target_field: cef
```

For JSON format, use `json.keys_under_root: true` instead.

### Syslog forwarding

Pipe stderr to a syslog forwarder via the systemd unit:

```ini
[Service]
StandardError=journal
```

Then configure the journal to forward to a remote syslog host via `journald.conf`:

```ini
[Journal]
ForwardToSyslog=yes
```
