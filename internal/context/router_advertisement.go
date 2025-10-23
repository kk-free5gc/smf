// WNC: Router Advertisement (RA) handling for IPv6 PDU sessions (Phase 2.5)
// Based on 3GPP TS 23.502 and open5gs implementation pattern
package context

import (
	"encoding/binary"
	"net"

	"github.com/free5gc/smf/internal/logger"
)

// PFCP Event IDs (3GPP TS 29.244)
const (
	EventIDRouterSolicitation uint32 = 26 // ENCP - Router Solicitation from UE
)

// IPv6 Router Advertisement packet structure (RFC 4861)
const (
	// ICMPv6 Type for Router Advertisement
	ICMPv6TypeRouterAdvertisement = 134

	// ICMPv6 Router Advertisement flags
	RAFlagManaged   = 0x80 // Managed address configuration flag (M)
	RAFlagOther     = 0x40 // Other configuration flag (O)
	RAFlagHomeAgent = 0x20 // Home Agent flag (H)

	// Default Router Advertisement parameters
	DefaultRARouterLifetime   = 1800 // seconds (30 minutes)
	DefaultRAReachableTime    = 0    // unspecified
	DefaultRARetransTimer     = 0    // unspecified
	DefaultRAPrefixValidTime  = 7200 // seconds (2 hours)
	DefaultRAPrefixPreferTime = 3600 // seconds (1 hour)

	// IPv6 RA Option Types (RFC 4861)
	RAOptionTypeSourceLinkLayer = 1
	RAOptionTypePrefixInfo      = 3
	RAOptionTypeMTU             = 5
)

// BuildRouterAdvertisement builds an IPv6 Router Advertisement packet
// This is modeled after the open5gs implementation
func BuildRouterAdvertisement(ipv6Prefix net.IP, prefixLen uint8) []byte {
	// ICMPv6 Router Advertisement format (RFC 4861 Section 4.2):
	// 0                   1                   2                   3
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |     Type      |     Code      |          Checksum             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Cur Hop Limit |M|O|H| Reserved|       Router Lifetime         |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                         Reachable Time                        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                          Retrans Timer                        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   Options ...
	// +-+-+-+-+-+-+-+-+-+-+-+-

	// Calculate total packet size
	// Base RA header: 16 bytes
	// Prefix Information Option: 32 bytes
	// Total: 48 bytes
	raPacket := make([]byte, 48)

	// ICMPv6 Header (8 bytes)
	raPacket[0] = ICMPv6TypeRouterAdvertisement // Type
	raPacket[1] = 0                              // Code
	// raPacket[2:4] - Checksum (calculated later)

	// Router Advertisement fields (8 bytes)
	raPacket[4] = 64                    // Cur Hop Limit (typical value)
	raPacket[5] = RAFlagManaged         // Flags: M=1 (managed address configuration)
	binary.BigEndian.PutUint16(raPacket[6:8], DefaultRARouterLifetime)
	binary.BigEndian.PutUint32(raPacket[8:12], DefaultRAReachableTime)
	binary.BigEndian.PutUint32(raPacket[12:16], DefaultRARetransTimer)

	// Prefix Information Option (RFC 4861 Section 4.6.2) - 32 bytes
	raPacket[16] = RAOptionTypePrefixInfo // Type
	raPacket[17] = 4                       // Length in units of 8 octets (4 * 8 = 32 bytes)
	raPacket[18] = prefixLen               // Prefix Length
	raPacket[19] = 0xC0                    // Flags: L=1 (on-link), A=1 (autonomous address-configuration)
	binary.BigEndian.PutUint32(raPacket[20:24], DefaultRAPrefixValidTime)
	binary.BigEndian.PutUint32(raPacket[24:28], DefaultRAPrefixPreferTime)
	// raPacket[28:32] - Reserved (already zero)

	// Copy IPv6 prefix (16 bytes)
	if ipv6Prefix != nil && ipv6Prefix.To16() != nil {
		copy(raPacket[32:48], ipv6Prefix.To16())
	}

	// Calculate ICMPv6 checksum
	// Note: In real implementation, this would need the IPv6 pseudo-header
	// For now, we'll set it to 0 as UPF/gtp5g will recalculate it
	binary.BigEndian.PutUint16(raPacket[2:4], 0)

	logger.PfcpLog.Tracef("WNC: Built Router Advertisement packet: %d bytes, prefix=%s/%d",
		len(raPacket), ipv6Prefix, prefixLen)

	return raPacket
}

// GetIPv6PrefixFromAddress extracts the network prefix from an IPv6 address
func GetIPv6PrefixFromAddress(ipv6Addr net.IP, prefixLen uint8) net.IP {
	if ipv6Addr == nil {
		return nil
	}

	ipv6 := ipv6Addr.To16()
	if ipv6 == nil {
		return nil
	}

	// Create a mask for the prefix length
	mask := net.CIDRMask(int(prefixLen), 128)

	// Apply mask to get network prefix
	prefix := make(net.IP, net.IPv6len)
	for i := 0; i < net.IPv6len; i++ {
		prefix[i] = ipv6[i] & mask[i]
	}

	return prefix
}

// ValidateIPv6Prefix checks if the provided IPv6 address is valid for RA
func ValidateIPv6Prefix(ipv6Prefix net.IP, prefixLen uint8) bool {
	if ipv6Prefix == nil {
		logger.PfcpLog.Warnln("WNC: Invalid IPv6 prefix: nil")
		return false
	}

	if ipv6Prefix.To16() == nil {
		logger.PfcpLog.Warnf("WNC: Invalid IPv6 prefix: not a valid IPv6 address %s", ipv6Prefix)
		return false
	}

	if prefixLen < 1 || prefixLen > 128 {
		logger.PfcpLog.Warnf("WNC: Invalid IPv6 prefix length: %d (must be 1-128)", prefixLen)
		return false
	}

	// Typical prefix lengths for mobile networks are /48, /56, /64
	if prefixLen != 48 && prefixLen != 56 && prefixLen != 64 {
		logger.PfcpLog.Infof("WNC: Unusual IPv6 prefix length: %d (typical: 48, 56, or 64)", prefixLen)
	}

	return true
}
