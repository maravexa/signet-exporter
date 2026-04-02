//go:build linux

// Package scanner implements network probe scanners.
// This file implements ICMP echo-request probing using golang.org/x/net/icmp,
// which handles the unprivileged/raw socket negotiation internally. On most
// Linux systems this requires CAP_NET_RAW or a permissive ping_group_range.
package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/maravexa/signet-exporter/pkg/netutil"
)

// ICMPScanner performs ICMP echo-request probes to discover live hosts.
// It complements the ARP scanner by detecting hosts reachable at L3 across
// routed boundaries where ARP does not reach.
type ICMPScanner struct {
	timeout   time.Duration // total wait for replies after all requests sent
	rateLimit time.Duration // delay between individual ICMP requests
	logger    *slog.Logger
}

// NewICMPScanner creates a new ICMP scanner.
// timeout is how long to wait for replies after sending all requests (default: 1s).
// rateLimit is the inter-packet delay (default: 200µs).
// If logger is nil, slog.Default() is used.
func NewICMPScanner(timeout time.Duration, rateLimit time.Duration, logger *slog.Logger) *ICMPScanner {
	if logger == nil {
		logger = slog.Default()
	}
	return &ICMPScanner{
		timeout:   timeout,
		rateLimit: rateLimit,
		logger:    logger,
	}
}

// Name returns the scanner identifier.
func (s *ICMPScanner) Name() string { return "icmp" }

// Scan sends ICMP echo requests to every usable address in subnet and returns
// the hosts that replied. Requires CAP_NET_RAW or a permissive ping_group_range.
func (s *ICMPScanner) Scan(ctx context.Context, subnet netip.Prefix) ([]ScanResult, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("opening ICMP socket failed — ensure CAP_NET_RAW capability is set: %w", err)
	}
	// conn is closed explicitly below after the timeout; the deferred close is a
	// safety net for early-return error paths.
	defer func() { _ = conn.Close() }()

	// Use the process PID masked to 16 bits as the ICMP identifier so replies
	// from other concurrent ping processes are filtered out.
	icmpID := os.Getpid() & 0xffff

	// Buffer the results channel at min(SubnetSize, 256) to avoid blocking the
	// listener goroutine while we drain after the scan.
	sz := netutil.SubnetSize(subnet)
	bufSize := 256
	if sz < 256 {
		bufSize = int(sz)
	}
	results := make(chan ScanResult, bufSize)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(results)
		s.listenForReplies(ctx, conn, icmpID, subnet, results)
	}()

	seq := 0
sendLoop:
	for ip := range netutil.SubnetAddrs(ctx, subnet) {
		pkt, err := buildEchoRequest(icmpID, seq)
		if err != nil {
			s.logger.Warn("failed to build ICMP request", "ip", ip, "error", err)
			continue
		}
		seq = (seq + 1) & 0xffff

		dst := &net.IPAddr{IP: net.IP(ip.AsSlice())}
		if _, err = conn.WriteTo(pkt, dst); err != nil {
			s.logger.Warn("failed to send ICMP request", "ip", ip, "err", err)
			continue
		}

		if s.rateLimit > 0 {
			timer := time.NewTimer(s.rateLimit)
			select {
			case <-ctx.Done():
				timer.Stop()
				break sendLoop
			case <-timer.C:
			}
		}
	}

	// Wait for replies: sleep for the timeout or until ctx is cancelled.
	select {
	case <-ctx.Done():
	case <-time.After(s.timeout):
	}

	// Closing the connection unblocks the listener's ReadFrom, causing it to exit.
	_ = conn.Close()
	wg.Wait()

	// Deduplicate by IP — keep the first response.
	seen := make(map[netip.Addr]bool)
	var out []ScanResult
	for r := range results {
		if !seen[r.IP] {
			seen[r.IP] = true
			out = append(out, r)
		}
	}
	return out, nil
}

// listenForReplies reads ICMP echo reply packets from conn until it is closed
// or ctx is cancelled, sending valid ScanResults for hosts within subnet to results.
func (s *ICMPScanner) listenForReplies(ctx context.Context, conn *icmp.PacketConn, expectedID int, subnet netip.Prefix, results chan<- ScanResult) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			// Normal exit: connection closed by Scan after timeout, or ctx done.
			return
		}
		srcIP, ok := parseEchoReply(buf[:n], addr, expectedID)
		if !ok || !subnet.Contains(srcIP) {
			continue
		}
		result := ScanResult{
			IP:        srcIP,
			MAC:       nil, // ICMP does not reveal MAC addresses
			Alive:     true,
			Source:    "icmp",
			Timestamp: time.Now(),
		}
		select {
		case results <- result:
		case <-ctx.Done():
			return
		default:
			// Buffer full — drop duplicate reply rather than blocking.
		}
	}
}

// buildEchoRequest constructs an ICMP echo request packet with the given
// identifier and sequence number. The payload is a short identifying string.
func buildEchoRequest(id, seq int) ([]byte, error) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("signet"), // short payload, identifiable in packet captures
		},
	}
	return msg.Marshal(nil)
}

// parseEchoReply validates buf as an ICMP echo reply matching expectedID and
// extracts the source IP from addr (the net.Addr returned by conn.ReadFrom).
// Returns a zero Addr and false if the packet is not a valid matching echo reply.
func parseEchoReply(buf []byte, addr net.Addr, expectedID int) (srcIP netip.Addr, ok bool) {
	if len(buf) < 4 {
		return netip.Addr{}, false
	}
	msg, err := icmp.ParseMessage(1, buf)
	if err != nil {
		return netip.Addr{}, false
	}
	if msg.Type != ipv4.ICMPTypeEchoReply {
		return netip.Addr{}, false
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return netip.Addr{}, false
	}
	if echo.ID != expectedID {
		return netip.Addr{}, false
	}

	// Source IP comes from the ReadFrom addr, not from the ICMP payload.
	switch a := addr.(type) {
	case *net.IPAddr:
		parsed, valid := netip.AddrFromSlice(a.IP)
		if !valid {
			return netip.Addr{}, false
		}
		return parsed.Unmap(), true
	case *net.UDPAddr:
		parsed, valid := netip.AddrFromSlice(a.IP)
		if !valid {
			return netip.Addr{}, false
		}
		return parsed.Unmap(), true
	default:
		return netip.Addr{}, false
	}
}
