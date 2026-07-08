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

// WNC: Addresses for the injected Router Advertisement (matches open5gs behaviour).
// Source is the network-side gateway link-local. Destination is the all-nodes
// multicast address: open5gs unicasts the RA to the UE's link-local (echoed from
// the RS), but free5gc's SMF only receives a PFCP event, not the RS packet, so it
// does not know the UE's self-chosen link-local. ff02::1 reaches the UE regardless.
var (
	raSourceLinkLocal = net.ParseIP("fe80::1")
	raDestAllNodes    = net.ParseIP("ff02::1")
)

// BuildRouterAdvertisement builds a COMPLETE IPv6 Router Advertisement packet
// (40-byte IPv6 header + ICMPv6 RA + Prefix Information Option), modeled on the
// on-the-wire open5gs RA. The gtp5g kernel injector transmits these bytes verbatim
// as an IPv6 packet (it prepends nothing), so the IPv6 header and a valid ICMPv6
// checksum MUST be built here.
//
// WNC FIX history: the previous version produced only the 48-byte ICMPv6 body with
// no IPv6 header (so the first byte 0x86 made the IP version read as 8, not 6), a
// zero checksum, and the M (managed) flag set (which tells the UE to use DHCPv6
// instead of SLAAC). All three are corrected below.
func BuildRouterAdvertisement(ipv6Prefix net.IP, prefixLen uint8) []byte {
	// ICMPv6 message: RA header (16 bytes) + Prefix Information Option (32 bytes).
	const icmpLen = 48
	icmp := make([]byte, icmpLen)

	// ICMPv6 RA header (16 bytes) - RFC 4861 Section 4.2
	icmp[0] = ICMPv6TypeRouterAdvertisement // Type = 134
	icmp[1] = 0                             // Code
	// icmp[2:4] - Checksum (computed after the pseudo-header is known)
	icmp[4] = 64 // Cur Hop Limit
	icmp[5] = 0  // Flags: M=0, O=0 -> pure SLAAC (was RAFlagManaged, which forced DHCPv6)
	binary.BigEndian.PutUint16(icmp[6:8], DefaultRARouterLifetime)
	binary.BigEndian.PutUint32(icmp[8:12], DefaultRAReachableTime)
	binary.BigEndian.PutUint32(icmp[12:16], DefaultRARetransTimer)

	// Prefix Information Option (32 bytes) - RFC 4861 Section 4.6.2
	icmp[16] = RAOptionTypePrefixInfo // Type = 3
	icmp[17] = 4                      // Length in units of 8 octets (4 * 8 = 32 bytes)
	icmp[18] = prefixLen              // Prefix Length
	icmp[19] = 0xC0                   // Flags: L=1 (on-link), A=1 (autonomous)
	binary.BigEndian.PutUint32(icmp[20:24], DefaultRAPrefixValidTime)
	binary.BigEndian.PutUint32(icmp[24:28], DefaultRAPrefixPreferTime)
	// icmp[28:32] - Reserved (already zero)
	if ipv6Prefix != nil && ipv6Prefix.To16() != nil {
		copy(icmp[32:48], ipv6Prefix.To16())
	}

	// IPv6 header (40 bytes) - RFC 8200
	src := raSourceLinkLocal.To16()
	dst := raDestAllNodes.To16()
	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60                                         // Version = 6, Traffic Class = 0
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(icmpLen)) // Payload Length
	ipv6[6] = 58                                           // Next Header = ICMPv6
	ipv6[7] = 255                                          // Hop Limit (NDP requires 255)
	copy(ipv6[8:24], src)
	copy(ipv6[24:40], dst)

	// ICMPv6 checksum over the IPv6 pseudo-header + ICMPv6 message
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(src, dst, icmp))

	raPacket := append(ipv6, icmp...)

	logger.PfcpLog.Tracef("WNC: Built Router Advertisement packet: %d bytes, prefix=%s/%d, src=%s dst=%s",
		len(raPacket), ipv6Prefix, prefixLen, src, dst)

	return raPacket
}

// icmpv6Checksum computes the ICMPv6 checksum over the IPv6 pseudo-header
// (src + dst + upper-layer length + next header 58) and the ICMPv6 message.
// The checksum field in icmp[2:4] must be zero when this is called.
func icmpv6Checksum(src, dst, icmp []byte) uint16 {
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(src[i])<<8 | uint32(src[i+1])
	}
	for i := 0; i < 16; i += 2 {
		sum += uint32(dst[i])<<8 | uint32(dst[i+1])
	}
	sum += uint32(len(icmp)) // upper-layer packet length
	sum += 58                // next header = ICMPv6
	for i := 0; i+1 < len(icmp); i += 2 {
		sum += uint32(icmp[i])<<8 | uint32(icmp[i+1])
	}
	if len(icmp)%2 == 1 {
		sum += uint32(icmp[len(icmp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
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
