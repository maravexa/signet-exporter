//go:build linux

// Package scanner implements network probe scanners.
// This file uses AF_PACKET raw sockets via github.com/mdlayher/packet, which
// provides a clean net.PacketConn wrapper without CGo. The alternative would be
// golang.org/x/sys/unix syscalls directly, but mdlayher/packet gives us deadline
// support and cleaner error handling for free.
package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/mdlayher/packet"

	"github.com/maravexa/signet-exporter/pkg/netutil"
)

// ethTypeARP is the EtherType for ARP frames (0x0806).
const ethTypeARP = 0x0806

// ARPScanner performs ARP sweep probes to discover live hosts and MAC addresses.
type ARPScanner struct {
	timeout   time.Duration // per-scan reply collection timeout
	rateLimit time.Duration // delay between individual ARP requests
	logger    *slog.Logger
}

// NewARPScanner creates a new ARP scanner.
// timeout is how long to wait for replies after sending all requests.
// rateLimit is the inter-packet delay (500µs default prevents switch overload).
// If logger is nil, slog.Default() is used.
func NewARPScanner(timeout time.Duration, rateLimit time.Duration, logger *slog.Logger) *ARPScanner {
	if logger == nil {
		logger = slog.Default()
	}
	return &ARPScanner{
		timeout:   timeout,
		rateLimit: rateLimit,
		logger:    logger,
	}
}

// Name returns the scanner identifier.
func (a *ARPScanner) Name() string { return "arp" }

// Scan broadcasts ARP requests for every usable address in subnet and returns
// the hosts that replied. Requires CAP_NET_RAW on the running process.
func (a *ARPScanner) Scan(ctx context.Context, subnet netip.Prefix) ([]ScanResult, error) {
	iface, srcIP, err := resolveInterface(subnet)
	if err != nil {
		return nil, fmt.Errorf("resolving interface for subnet %s: %w", subnet, err)
	}

	conn, err := packet.Listen(iface, packet.Raw, ethTypeARP, nil)
	if err != nil {
		return nil, fmt.Errorf("opening raw socket failed — ensure CAP_NET_RAW capability is set: %w", err)
	}
	// conn is closed explicitly below after the timeout; the deferred close is a
	// safety net for early-return error paths.
	defer func() { _ = conn.Close() }()

	// Keep a collector running while replies arrive. A bounded buffered channel
	// drained only after the capture window would silently lose hosts on subnets
	// with more replies than its capacity. Back-pressure is preferable to a
	// false "complete" scan with missing hosts.
	results := make(chan ScanResult)
	var collected []ScanResult
	var collectorWG sync.WaitGroup
	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		collected = collectARPResults(results)
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(results)
		a.listenForReplies(ctx, conn, subnet, results)
	}()

	// Send ARP "who-has" requests for every usable IP in the subnet.
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
sendLoop:
	for ip := range netutil.SubnetAddrs(ctx, subnet) {
		pkt, err := buildARPRequest(iface.HardwareAddr, srcIP, ip)
		if err != nil {
			a.logger.Warn("failed to build ARP request", "ip", ip, "err", err)
			continue
		}
		if _, err = conn.WriteTo(pkt, &packet.Addr{HardwareAddr: broadcast}); err != nil {
			a.logger.Warn("failed to send ARP request", "ip", ip, "err", err)
			continue
		}
		if a.rateLimit > 0 {
			timer := time.NewTimer(a.rateLimit)
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
	case <-time.After(a.timeout):
	}

	// Closing the connection unblocks the listener's ReadFrom, causing it to exit.
	_ = conn.Close()
	wg.Wait()
	collectorWG.Wait()

	// A cancelled scan is not a successful observation window. Do not return
	// partial discovery data as a normal result, because callers cannot safely
	// distinguish it from a complete sweep.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return collected, nil
}

// collectARPResults drains a reply stream until closed while grouping replies
// incrementally. This keeps normal retransmissions and hostile reply floods
// from accumulating an unbounded raw-reply slice.
func collectARPResults(results <-chan ScanResult) []ScanResult {
	acc := newARPReplyAccumulator()
	for r := range results {
		acc.add(arpReply{
			IP:        r.IP,
			MAC:       r.MAC,
			Timestamp: r.Timestamp,
		})
	}
	return acc.results()
}

// arpReply holds a single parsed ARP reply for intermediate grouping.
type arpReply struct {
	IP        netip.Addr
	MAC       net.HardwareAddr
	Timestamp time.Time
}

// groupARPReplies groups raw ARP replies by IP, detecting when multiple distinct
// MACs claim the same IP within a single scan window.
//
// The lexicographically lowest MAC claimant per IP becomes the primary
// ScanResult. Additional retained claimants are sorted into DuplicateMACs.
// The bounded retained set also keeps the lowest MAC values, so packet arrival
// order cannot change the conflict result. Retransmissions from the same MAC are
// silently ignored. DuplicateChecked is always true on ARP results.
func groupARPReplies(replies []arpReply) []ScanResult {
	acc := newARPReplyAccumulator()
	for _, r := range replies {
		acc.add(r)
	}
	return acc.results()
}

type arpIPGroup struct {
	claims    map[string]arpReply
	truncated bool
}

type arpReplyAccumulator struct {
	groups map[netip.Addr]*arpIPGroup
	order  []netip.Addr
}

func newARPReplyAccumulator() *arpReplyAccumulator {
	return &arpReplyAccumulator{groups: make(map[netip.Addr]*arpIPGroup)}
}

func (a *arpReplyAccumulator) add(r arpReply) {
	g, ok := a.groups[r.IP]
	if !ok {
		a.groups[r.IP] = &arpIPGroup{
			claims: map[string]arpReply{r.MAC.String(): {IP: r.IP, MAC: append(net.HardwareAddr(nil), r.MAC...), Timestamp: r.Timestamp}},
		}
		a.order = append(a.order, r.IP)
		return
	}
	macStr := r.MAC.String()
	if existing, exists := g.claims[macStr]; exists {
		if r.Timestamp.Before(existing.Timestamp) {
			existing.Timestamp = r.Timestamp
			g.claims[macStr] = existing
		}
		return
	}
	// Retain the lexicographically lowest bounded claimant set, independent of
	// packet arrival order. The smallest MAC is the deterministic primary.
	if len(g.claims) >= maxDuplicateMACsPerIP+1 {
		largest := ""
		for claim := range g.claims {
			if claim > largest {
				largest = claim
			}
		}
		if macStr >= largest {
			g.truncated = true
			return
		}
		delete(g.claims, largest)
		g.truncated = true
	}
	g.claims[macStr] = arpReply{IP: r.IP, MAC: append(net.HardwareAddr(nil), r.MAC...), Timestamp: r.Timestamp}
}

func (a *arpReplyAccumulator) results() []ScanResult {
	out := make([]ScanResult, 0, len(a.groups))
	for _, ip := range a.order {
		g := a.groups[ip]
		claimKeys := make([]string, 0, len(g.claims))
		for claim := range g.claims {
			claimKeys = append(claimKeys, claim)
		}
		sort.Strings(claimKeys)
		primary := g.claims[claimKeys[0]]
		duplicates := make([]net.HardwareAddr, 0, len(claimKeys)-1)
		for _, claim := range claimKeys[1:] {
			duplicates = append(duplicates, append(net.HardwareAddr(nil), g.claims[claim].MAC...))
		}
		metadata := map[string]string(nil)
		if g.truncated {
			metadata = map[string]string{"duplicate_claimants_truncated": "true"}
		}
		out = append(out, ScanResult{
			IP:               primary.IP,
			MAC:              primary.MAC,
			Alive:            true,
			Source:           "arp",
			Timestamp:        primary.Timestamp,
			DuplicateChecked: true,
			DuplicateMACs:    duplicates,
			Metadata:         metadata,
		})
	}
	return out
}

// listenForReplies reads ARP reply frames from conn until it is closed or ctx
// is cancelled, sending valid ScanResults for hosts within subnet to results.
func (a *ARPScanner) listenForReplies(ctx context.Context, conn net.PacketConn, subnet netip.Prefix, results chan<- ScanResult) {
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			// Normal exit: connection closed by Scan after timeout, or ctx done.
			return
		}
		mac, ip, ok := parseARPReply(buf[:n])
		if !ok || !subnet.Contains(ip) {
			continue
		}
		result := ScanResult{
			IP:        ip,
			MAC:       mac,
			Alive:     true,
			Source:    "arp",
			Timestamp: time.Now(),
		}
		select {
		case results <- result:
		case <-ctx.Done():
			return
		}
	}
}

// buildARPRequest constructs a complete Ethernet frame containing an ARP
// "who-has" request. Returns the raw 42-byte frame ready for AF_PACKET.
//
// Frame layout:
//
//	Ethernet header (14 bytes): dst=broadcast, src=srcMAC, ethertype=0x0806
//	ARP payload   (28 bytes): hw=Ethernet, proto=IPv4, op=request
func buildARPRequest(srcMAC net.HardwareAddr, srcIP netip.Addr, dstIP netip.Addr) ([]byte, error) {
	if !srcIP.Is4() {
		return nil, fmt.Errorf("srcIP %s is not an IPv4 address", srcIP)
	}
	if !dstIP.Is4() {
		return nil, fmt.Errorf("dstIP %s is not an IPv4 address", dstIP)
	}

	frame := make([]byte, 42)

	// Ethernet header
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // dst: broadcast
	copy(frame[6:12], srcMAC)                                    // src
	binary.BigEndian.PutUint16(frame[12:14], ethTypeARP)         // EtherType 0x0806

	// ARP payload
	binary.BigEndian.PutUint16(frame[14:16], 0x0001) // hardware type: Ethernet
	binary.BigEndian.PutUint16(frame[16:18], 0x0800) // protocol type: IPv4
	frame[18] = 6                                    // hardware address length
	frame[19] = 4                                    // protocol address length
	binary.BigEndian.PutUint16(frame[20:22], 0x0001) // operation: request
	copy(frame[22:28], srcMAC)                       // sender hardware address
	s4 := srcIP.As4()
	copy(frame[28:32], s4[:]) // sender protocol address
	// target hardware address [32:38] stays all-zeros (unknown)
	d4 := dstIP.As4()
	copy(frame[38:42], d4[:]) // target protocol address

	return frame, nil
}

// parseARPReply parses a raw Ethernet frame and extracts the sender's MAC and IP
// from an ARP reply. Returns zero values and false if the frame is not a valid
// ARP reply.
func parseARPReply(frame []byte) (mac net.HardwareAddr, ip netip.Addr, ok bool) {
	if len(frame) < 42 {
		return nil, netip.Addr{}, false
	}
	// EtherType must be ARP
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypeARP {
		return nil, netip.Addr{}, false
	}
	// Hardware type must be Ethernet, protocol type must be IPv4
	if binary.BigEndian.Uint16(frame[14:16]) != 0x0001 {
		return nil, netip.Addr{}, false
	}
	if binary.BigEndian.Uint16(frame[16:18]) != 0x0800 {
		return nil, netip.Addr{}, false
	}
	if frame[18] != 6 || frame[19] != 4 {
		return nil, netip.Addr{}, false
	}
	// Operation must be reply (0x0002)
	if binary.BigEndian.Uint16(frame[20:22]) != 0x0002 {
		return nil, netip.Addr{}, false
	}

	// Extract sender MAC — copy to avoid aliasing the buffer
	hwCopy := make(net.HardwareAddr, 6)
	copy(hwCopy, frame[22:28])

	// Extract sender IP
	ipBytes := [4]byte{frame[28], frame[29], frame[30], frame[31]}
	senderIP := netip.AddrFrom4(ipBytes)

	return hwCopy, senderIP, true
}

// resolveInterface finds the network interface whose address falls within subnet.
// Returns the interface and its first IPv4 address within the subnet.
func resolveInterface(subnet netip.Prefix) (*net.Interface, netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, netip.Addr{}, fmt.Errorf("listing network interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			var ip netip.Addr
			switch v := a.(type) {
			case *net.IPNet:
				parsed, ok := netip.AddrFromSlice(v.IP)
				if !ok {
					continue
				}
				ip = parsed.Unmap()
			case *net.IPAddr:
				parsed, ok := netip.AddrFromSlice(v.IP)
				if !ok {
					continue
				}
				ip = parsed.Unmap()
			default:
				continue
			}

			if subnet.Contains(ip) {
				ifaceCopy := iface
				return &ifaceCopy, ip, nil
			}
		}
	}

	return nil, netip.Addr{}, fmt.Errorf("no interface found with address in subnet %s", subnet)
}
