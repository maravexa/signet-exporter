package audit

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// CEFFormatter writes audit events in Common Event Format (CEF) for SIEM integration.
// CEF line structure:
//
//	CEF:0|Signet|signet-exporter|<version>|<eventID>|<eventName>|<severity>|<extensions>
//
// Each event method writes a single CEF line to the underlying writer.
// CEFFormatter satisfies the unexported auditBackend interface.
type CEFFormatter struct {
	w       io.Writer
	version string // binary version injected into CEF header
}

// NewCEFFormatter creates a CEFFormatter that writes to w.
// version is embedded in the CEF Device Version header field.
func NewCEFFormatter(w io.Writer, version string) *CEFFormatter {
	if version == "" {
		version = "dev"
	}
	return &CEFFormatter{w: w, version: version}
}

// cef event IDs and severities.
const (
	cefIDNewHost           = 100
	cefIDMACIPChange       = 200
	cefIDUnauthorized      = 300
	cefIDDuplicateIP       = 400
	cefIDScanCompleted     = 500
	cefIDScanError         = 600
	cefIDConfigReloaded    = 700
	cefIDCertReloaded      = 800
	cefIDHostDisappeared   = 150
	cefIDHostExpired       = 160
	cefIDScanCycleComplete = 550

	cefIDRemoteWriteStarted             = 900
	cefIDRemoteWriteEndpointUnreachable = 910
	cefIDRemoteWriteConfigReloaded      = 920
	cefIDRemoteWriteRecovered           = 930
)

// cefEscapeHeader escapes characters that are significant in CEF header fields
// (pipe-delimited). Backslash must be escaped first to avoid double-escaping.
func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	return s
}

// cefEscape escapes characters that are significant in CEF extension values.
// Backslash must be escaped first to avoid double-escaping.
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\n`)
	return s
}

// writeLine formats and writes a single CEF line to the underlying writer.
// severity is a numeric string 0–10 per the CEF spec.
func (c *CEFFormatter) writeLine(eventID int, name string, severity int, extensions string) {
	line := fmt.Sprintf("CEF:0|Signet|signet-exporter|%s|%d|%s|%d|%s\n",
		cefEscapeHeader(c.version),
		eventID,
		cefEscapeHeader(name),
		severity,
		extensions,
	)
	_, _ = io.WriteString(c.w, line)
}

// ext builds a CEF extension string from alternating key/value pairs.
// Keys are assumed to be safe alphanumeric identifiers (no escaping).
// Values are CEF-escaped.
func ext(pairs ...string) string {
	if len(pairs)%2 != 0 {
		pairs = pairs[:len(pairs)-1]
	}
	parts := make([]string, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		parts = append(parts, pairs[i]+"="+cefEscape(pairs[i+1]))
	}
	return strings.Join(parts, " ")
}

// NewHost logs discovery of a new host.
func (c *CEFFormatter) NewHost(ip net.IP, subnet string, mac net.HardwareAddr, vendor, hostname string) {
	c.writeLine(cefIDNewHost, "New Host Discovered", 3, ext(
		"src", ip.String(),
		"subnet", subnet,
		"mac", mac.String(),
		"vendor", vendor,
		"hostname", hostname,
	))
}

// MACIPChange logs a MAC address change for an IP.
func (c *CEFFormatter) MACIPChange(ip net.IP, subnet string, oldMAC, newMAC net.HardwareAddr, oldVendor, newVendor string) {
	c.writeLine(cefIDMACIPChange, "MAC-IP Binding Changed", 7, ext(
		"src", ip.String(),
		"subnet", subnet,
		"oldMac", oldMAC.String(),
		"newMac", newMAC.String(),
		"oldVendor", oldVendor,
		"newVendor", newVendor,
	))
}

// HostDisappeared logs a host going stale.
func (c *CEFFormatter) HostDisappeared(ip net.IP, subnet string, mac net.HardwareAddr, vendor string, lastSeen time.Time) {
	c.writeLine(cefIDHostDisappeared, "Host Disappeared", 3, ext(
		"src", ip.String(),
		"subnet", subnet,
		"mac", mac.String(),
		"vendor", vendor,
		"lastSeen", lastSeen.UTC().Format(time.RFC3339),
	))
}

// HostExpired logs a host being pruned by the TTL eviction mechanism.
func (c *CEFFormatter) HostExpired(ip string, subnet string, lastSeen time.Time) {
	c.writeLine(cefIDHostExpired, "Host Expired", 3, ext(
		"src", ip,
		"subnet", subnet,
		"lastSeen", lastSeen.UTC().Format(time.RFC3339),
	))
}

// UnauthorizedDevice logs detection of a device not on the MAC allowlist.
func (c *CEFFormatter) UnauthorizedDevice(ip net.IP, subnet string, mac net.HardwareAddr, vendor string) {
	c.writeLine(cefIDUnauthorized, "Unauthorized Device Detected", 9, ext(
		"src", ip.String(),
		"subnet", subnet,
		"mac", mac.String(),
		"vendor", vendor,
	))
}

// DuplicateIP logs detection of multiple MACs claiming the same IP.
func (c *CEFFormatter) DuplicateIP(ip net.IP, subnet string, primaryMAC net.HardwareAddr, duplicateMACs []net.HardwareAddr) {
	dups := make([]string, len(duplicateMACs))
	for i, m := range duplicateMACs {
		dups[i] = m.String()
	}
	c.writeLine(cefIDDuplicateIP, "Duplicate IP Detected", 7, ext(
		"src", ip.String(),
		"subnet", subnet,
		"primaryMac", primaryMAC.String(),
		"duplicateMacs", strings.Join(dups, ","),
	))
}

// ScanCycleComplete logs completion of a full scan cycle.
func (c *CEFFormatter) ScanCycleComplete(subnet string, hostsFound int, duration time.Duration, scannersRun []string) {
	c.writeLine(cefIDScanCycleComplete, "Scan Cycle Complete", 0, ext(
		"subnet", subnet,
		"hostsFound", fmt.Sprintf("%d", hostsFound),
		"durationMs", fmt.Sprintf("%d", duration.Milliseconds()),
		"scannersRun", strings.Join(scannersRun, ","),
	))
}

// ScanCompleted logs completion of a single scanner pass.
func (c *CEFFormatter) ScanCompleted(subnet, scanner string, duration time.Duration, hostsFound int) {
	c.writeLine(cefIDScanCompleted, "Scanner Pass Completed", 0, ext(
		"subnet", subnet,
		"scanner", scanner,
		"durationMs", fmt.Sprintf("%d", duration.Milliseconds()),
		"hostsFound", fmt.Sprintf("%d", hostsFound),
	))
}

// ScanError logs a scanner failure.
func (c *CEFFormatter) ScanError(subnet, scanner string, err error) {
	c.writeLine(cefIDScanError, "Scanner Error", 5, ext(
		"subnet", subnet,
		"scanner", scanner,
		"msg", err.Error(),
	))
}

// ConfigReloaded logs a configuration reload.
func (c *CEFFormatter) ConfigReloaded(changedFields []string) {
	c.writeLine(cefIDConfigReloaded, "Configuration Reloaded", 2, ext(
		"changedFields", strings.Join(changedFields, ","),
	))
}

// RemoteWriteStarted logs the first successful push to the remote write endpoint.
func (c *CEFFormatter) RemoteWriteStarted(endpoint, authType string) {
	c.writeLine(cefIDRemoteWriteStarted, "Remote Write Started", 2, ext(
		"endpoint", endpoint,
		"authType", authType,
	))
}

// RemoteWriteEndpointUnreachable logs a sustained-failure threshold crossing.
func (c *CEFFormatter) RemoteWriteEndpointUnreachable(endpoint string, downFor time.Duration, lastErr string) {
	c.writeLine(cefIDRemoteWriteEndpointUnreachable, "Remote Write Endpoint Unreachable", 7, ext(
		"endpoint", endpoint,
		"downForMs", fmt.Sprintf("%d", downFor.Milliseconds()),
		"msg", lastErr,
	))
}

// RemoteWriteConfigReloaded logs a SIGHUP-driven remote-write configuration change.
func (c *CEFFormatter) RemoteWriteConfigReloaded(changes []string) {
	c.writeLine(cefIDRemoteWriteConfigReloaded, "Remote Write Config Reloaded", 2, ext(
		"changes", strings.Join(changes, ","),
	))
}

// RemoteWriteRecovered logs the first success following a sustained outage.
func (c *CEFFormatter) RemoteWriteRecovered(endpoint string, downFor time.Duration) {
	c.writeLine(cefIDRemoteWriteRecovered, "Remote Write Recovered", 2, ext(
		"endpoint", endpoint,
		"downForMs", fmt.Sprintf("%d", downFor.Milliseconds()),
	))
}

// CertReloaded logs a TLS certificate reload.
func (c *CEFFormatter) CertReloaded(certPath string, certErr error) {
	if certErr != nil {
		c.writeLine(cefIDCertReloaded, "TLS Certificate Reload Failed", 7, ext(
			"certPath", certPath,
			"msg", certErr.Error(),
		))
		return
	}
	c.writeLine(cefIDCertReloaded, "TLS Certificate Reloaded", 2, ext(
		"certPath", certPath,
	))
}
