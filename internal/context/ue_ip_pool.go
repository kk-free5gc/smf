package context

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/free5gc/smf/internal/context/pool"
	"github.com/free5gc/smf/internal/logger"
	"github.com/free5gc/smf/pkg/factory"
)

// UeIPPool represent IP address pool for UE (supports both IPv4 and IPv6)
type UeIPPool struct {
	ueSubNet *net.IPNet
	pool     *pool.LazyReusePool
	isIPv6   bool // true if this pool manages IPv6 addresses
	// WNC: Store original factory configuration for round-trip fidelity
	factoryIPv4Pool *factory.UEIPPool     // Original IPv4 pool config (nil for IPv6 pools)
	factoryIPv6Pool *factory.UEIPv6Pool   // Original IPv6 pool config (nil for IPv4 pools)
}

func NewUEIPPool(factoryPool *factory.UEIPPool) *UeIPPool {
	_, ipNet, err := net.ParseCIDR(factoryPool.Cidr)
	if err != nil {
		logger.InitLog.Errorln(err)
		return nil
	}

	minAddr, maxAddr, err := calcAddrRange(ipNet)
	if err != nil {
		logger.InitLog.Errorln(err)
		return nil
	}

	// Promote IPv4 32-bit addresses to uint64 for widened pool API
	newPool, err := pool.NewLazyReusePool(uint64(minAddr), uint64(maxAddr))
	if err != nil {
		logger.InitLog.Errorln(err)
		return nil
	}

	ueIPPool := &UeIPPool{
		ueSubNet:        ipNet,
		pool:            newPool,
		isIPv6:          false, // IPv4 pool
		factoryIPv4Pool: factoryPool, // WNC: Preserve original config for round-trip
		factoryIPv6Pool: nil,
	}
	return ueIPPool
}

// NewUEIPv6Pool creates a UeIPPool from factory IPv6 pool configuration
// Note: For IPv6, the pool manages the full 64-bit Interface Identifier (IID)
// This preserves static IPv6 bindings with all bits in the IID
func NewUEIPv6Pool(factoryPool *factory.UEIPv6Pool) *UeIPPool {
	_, ipNet, err := net.ParseCIDR(factoryPool.Prefix)
	if err != nil {
		logger.InitLog.Errorf("WNC: Failed to parse IPv6 prefix %s: %v", factoryPool.Prefix, err)
		return nil
	}

	// WNC: For IPv6, we manage the full 64-bit IID (bytes 8-15)
	// This preserves static IPv6 bindings with non-zero bits anywhere in the IID
	minAddr, maxAddr, err := calcIPv6AddrRange(ipNet, factoryPool.UePrefixLength)
	if err != nil {
		logger.InitLog.Errorf("WNC: Failed to calculate IPv6 address range: %v", err)
		return nil
	}

	newPool, err := pool.NewLazyReusePool(minAddr, maxAddr)
	if err != nil {
		logger.InitLog.Errorf("WNC: Failed to create IPv6 pool: %v", err)
		return nil
	}

	ueIPv6Pool := &UeIPPool{
		ueSubNet:        ipNet,
		pool:            newPool,
		isIPv6:          true, // IPv6 pool
		factoryIPv4Pool: nil,
		factoryIPv6Pool: factoryPool, // WNC: Preserve original config for round-trip
	}

	logger.InitLog.Infof("WNC: Created IPv6 pool from prefix %s (UE prefix length: /%d)",
		factoryPool.Prefix, factoryPool.UePrefixLength)

	return ueIPv6Pool
}

func (ueIPPool *UeIPPool) Allocate(request net.IP) net.IP {
	var allocVal uint64
	var ok bool
	if request != nil {
		// Use helper function to extract pool index from requested IP
		allocVal = ueIPPool.ipToPoolIndex(request)
		ok = ueIPPool.pool.Use(allocVal)
		if !ok {
			logger.CtxLog.Warnf("IP[%s] is used in Pool[%+v]", request, ueIPPool.ueSubNet)
			return nil
		}
		// if allocated request IP address
		goto RETURNIP
	}

	allocVal, ok = ueIPPool.pool.Allocate()
	if !ok {
		logger.CtxLog.Warnf("Pool is empty: %+v", ueIPPool.ueSubNet)
		return nil
	}

RETURNIP:
	// Use helper function to construct IP from pool index
	retIP := ueIPPool.poolIndexToIP(allocVal)
	if ueIPPool.isIPv6 {
		logger.CtxLog.Infof("WNC: Allocated UE IPv6 address: %s", retIP)
	} else {
		logger.CtxLog.Infof("Allocated UE IP address: %s", retIP)
	}
	return retIP
}

func (ueIPPool *UeIPPool) Exclude(excludePool *UeIPPool) error {
	excludeMin := excludePool.pool.Min()
	excludeMax := excludePool.pool.Max()
	if err := ueIPPool.pool.Reserve(excludeMin, excludeMax); err != nil {
		return fmt.Errorf("exclude uePool fail: %v", err)
	}
	return nil
}

func (u *UeIPPool) Pool() *pool.LazyReusePool {
	return u.pool
}

// ipToPoolIndex extracts the pool index from an IP address
// For IPv4: converts the entire 32-bit address to uint32
// For IPv6: extracts the host portion (IID or partial IID) as the pool index
func (ueIPPool *UeIPPool) ipToPoolIndex(addr net.IP) uint64 {
	if ueIPPool.isIPv6 {
		// WNC: For IPv6, extract only the host portion based on the UE prefix length
		// For prefixes > /64, we must mask out the network bits in bytes 8-15
		ip16 := addr.To16()
		if ip16 == nil {
			logger.CtxLog.Warnf("WNC: Invalid IPv6 address: %s", addr)
			return 0
		}

		// Extract bytes 8-15 as a 64-bit value
		iidValue := binary.BigEndian.Uint64(ip16[8:16])

		// Determine how many host bits are available
		uePrefixLength := ueIPPool.factoryIPv6Pool.UePrefixLength
		if uePrefixLength > 64 {
			// For prefixes longer than /64, only some bits of bytes 8-15 are host bits
			// Example: /80 has 48 host bits (bits 80-127), so we mask to keep only those
			hostBits := 128 - uePrefixLength
			hostMask := uint64(0xFFFFFFFFFFFFFFFF) >> (64 - hostBits)
			return iidValue & hostMask
		}

		// For /64 or shorter, the full 64-bit IID is the pool index
		return iidValue
	}
	// For IPv4, use the entire address (returns uint64 for consistency)
	ip4 := addr.To4()
	if ip4 == nil {
		logger.CtxLog.Warnf("Invalid IPv4 address: %s", addr)
		return 0
	}
	return uint64(binary.BigEndian.Uint32(ip4))
}

// poolIndexToIP constructs an IP address from a pool index
// For IPv4: directly converts uint32 to 4-byte address
// For IPv6: combines the pool's prefix with the host portion (IID or partial IID)
func (ueIPPool *UeIPPool) poolIndexToIP(index uint64) net.IP {
	if ueIPPool.isIPv6 {
		// WNC: For IPv6, combine the network prefix with the host portion
		// For prefixes > /64, we must preserve the network bits in bytes 8-15
		ip := make(net.IP, 16)
		copy(ip, ueIPPool.ueSubNet.IP.To16())

		// Determine how many host bits are available
		uePrefixLength := ueIPPool.factoryIPv6Pool.UePrefixLength
		if uePrefixLength > 64 {
			// For prefixes longer than /64, only some bits of bytes 8-15 are host bits
			// Example: /80 has 48 host bits (bits 80-127), so bytes 8-9 are network bits
			hostBits := 128 - uePrefixLength
			hostMask := uint64(0xFFFFFFFFFFFFFFFF) >> (64 - hostBits)

			// Read existing network portion from bytes 8-15
			networkPortion := binary.BigEndian.Uint64(ip[8:16])
			// Mask out the host bits and combine with the index
			networkPortion = (networkPortion & ^hostMask) | (index & hostMask)
			binary.BigEndian.PutUint64(ip[8:16], networkPortion)
		} else {
			// For /64 or shorter, the full 64-bit IID (bytes 8-15) is available
			binary.BigEndian.PutUint64(ip[8:16], index)
		}
		return ip
	}
	// For IPv4, direct conversion
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(index))
	return buf
}

func (ueIPPool *UeIPPool) Release(addr net.IP) {
	// Use helper function to extract pool index from IP address
	addrVal := ueIPPool.ipToPoolIndex(addr)
	res := ueIPPool.pool.Free(addrVal)
	if !res {
		logger.CtxLog.Warnf("failed to release UE Address: %s", addr)
	} else if ueIPPool.isIPv6 {
		logger.CtxLog.Debugf("WNC: Released IPv6 address: %s", addr)
	}
	logger.CtxLog.Debug(ueIPPool.dump())
}

func (ueIPPool *UeIPPool) dump() string {
	str := "["
	elements := ueIPPool.pool.Dump()
	for index, element := range elements {
		// Use helper function to construct IP addresses from pool indices
		firstAddr := ueIPPool.poolIndexToIP(element[0])
		lastAddr := ueIPPool.poolIndexToIP(element[1])
		if index > 0 {
			str += ("->")
		}
		str += fmt.Sprintf("{%s - %s}", firstAddr.String(), lastAddr.String())
	}
	str += ("]")
	return str
}

func isOverlap(pools []*UeIPPool) bool {
	if len(pools) < 2 {
		// no need to check
		return false
	}
	for i := 0; i < len(pools)-1; i++ {
		for j := i + 1; j < len(pools); j++ {
			// For IPv6 pools, numeric ranges may be identical but represent different
			// actual IP addresses due to different prefixes. Only check overlap if:
			// 1. Both are IPv4, OR
			// 2. Both are IPv6 with the same prefix
			bothIPv6 := pools[i].isIPv6 && pools[j].isIPv6
			bothIPv4 := !pools[i].isIPv6 && !pools[j].isIPv6

			if bothIPv4 {
				// IPv4: numeric range overlap means actual overlap
				if pools[i].pool.IsJoint(pools[j].pool) {
					logger.InitLog.Warnf("Overlap detected between IPv4 pools: %s and %s",
						pools[i].ueSubNet.String(), pools[j].ueSubNet.String())
					return true
				}
			} else if bothIPv6 {
				// IPv6: only overlaps if same prefix AND numeric range overlap
				samePrefixIPv6 := pools[i].ueSubNet.IP.Equal(pools[j].ueSubNet.IP) &&
					pools[i].ueSubNet.Mask.String() == pools[j].ueSubNet.Mask.String()

				if samePrefixIPv6 && pools[i].pool.IsJoint(pools[j].pool) {
					logger.InitLog.Warnf("Overlap detected between IPv6 pools with same prefix: %s and %s",
						pools[i].ueSubNet.String(), pools[j].ueSubNet.String())
					return true
				}
			} else {
				// Mixed IPv4/IPv6: cannot overlap (different address families)
				continue
			}
		}
	}
	return false
}

func calcAddrRange(ipNet *net.IPNet) (minAddr, maxAddr uint32, err error) {
	maskVal := binary.BigEndian.Uint32(ipNet.Mask)
	baseIPVal := binary.BigEndian.Uint32(ipNet.IP)
	// move removing network and broadcast address later
	minAddr = (baseIPVal & maskVal)
	maxAddr = (baseIPVal | ^maskVal)
	if minAddr > maxAddr {
		return minAddr, maxAddr, errors.New("Mask is invalid.")
	}
	return minAddr, maxAddr, nil
}

// calcIPv6AddrRange calculates the address range for IPv6 pools
// WNC: The range is capped based on the actual number of host bits available
// For prefixes > /64, we manage only a subset of the 64-bit space
func calcIPv6AddrRange(ipNet *net.IPNet, uePrefixLength int) (minAddr, maxAddr uint64, err error) {
	// WNC: Calculate the number of host bits available for allocation
	// For /64, we have 64 host bits; for /80, we have 48 host bits, etc.

	if uePrefixLength > 128 || uePrefixLength < 1 {
		return 0, 0, fmt.Errorf("invalid UE prefix length: %d (must be 1-128)", uePrefixLength)
	}

	hostBits := 128 - uePrefixLength

	// Cap the pool range based on actual host bits available
	if hostBits >= 64 {
		// For /64 or shorter prefixes, use subset of 64-bit IID space
		// Avoid ::0 and ::ffff:ffff:ffff:ffff for safety
		minAddr = 1
		maxAddr = 0xFFFFFFFFFFFFFFFE
	} else if hostBits == 1 {
		// /127 has only 1 host bit - two addresses [0, 1]
		minAddr = 0
		maxAddr = 1
	} else if hostBits > 1 {
		// For prefixes longer than /64 (e.g., /80 with 48 host bits)
		// Cap the range to prevent generating indices that would overflow into network bits
		minAddr = 1 // Avoid all-zeros
		maxAddr = (uint64(1) << hostBits) - 2 // Avoid all-ones
		// Example: /80 (48 host bits) → maxAddr = 2^48 - 2 = 0xFFFFFFFFFFFE
	} else {
		// /128 has no host bits - single address only
		minAddr = 0
		maxAddr = 0
	}

	ones, _ := ipNet.Mask.Size()
	logger.InitLog.Infof("WNC: IPv6 pool range: %d to %d (prefix: /%d, UE prefix: /%d, host bits: %d)",
		minAddr, maxAddr, ones, uePrefixLength, hostBits)

	return minAddr, maxAddr, nil
}
