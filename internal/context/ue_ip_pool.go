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

	newPool, err := pool.NewLazyReusePool(int(minAddr), int(maxAddr))
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
// Note: For IPv6, the pool manages a simplified range based on the lower 32 bits
// This is sufficient for /64 prefixes with IID allocation
func NewUEIPv6Pool(factoryPool *factory.UEIPv6Pool) *UeIPPool {
	_, ipNet, err := net.ParseCIDR(factoryPool.Prefix)
	if err != nil {
		logger.InitLog.Errorf("WNC: Failed to parse IPv6 prefix %s: %v", factoryPool.Prefix, err)
		return nil
	}

	// For IPv6, we use a simplified pool allocation strategy
	// We manage the lower 32 bits of the address space within the prefix
	// This works well for typical /48 or /64 delegations
	minAddr, maxAddr, err := calcIPv6AddrRange(ipNet, factoryPool.UePrefixLength)
	if err != nil {
		logger.InitLog.Errorf("WNC: Failed to calculate IPv6 address range: %v", err)
		return nil
	}

	newPool, err := pool.NewLazyReusePool(int(minAddr), int(maxAddr))
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
	var allocVal int
	var ok bool
	if request != nil {
		// Use helper function to extract pool index from requested IP
		allocVal = int(ueIPPool.ipToPoolIndex(request))
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
	retIP := ueIPPool.poolIndexToIP(uint32(allocVal))
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
// For IPv6: extracts the lower 32 bits (IID part) as the pool index
func (ueIPPool *UeIPPool) ipToPoolIndex(addr net.IP) uint32 {
	if ueIPPool.isIPv6 {
		// For IPv6, use the last 4 bytes (lower 32 bits of the 128-bit address)
		// This assumes the pool manages the IID portion within the prefix
		ip16 := addr.To16()
		if ip16 == nil {
			logger.CtxLog.Warnf("Invalid IPv6 address: %s", addr)
			return 0
		}
		// Extract bytes 12-15 (last 32 bits)
		return binary.BigEndian.Uint32(ip16[12:16])
	}
	// For IPv4, use the entire address
	ip4 := addr.To4()
	if ip4 == nil {
		logger.CtxLog.Warnf("Invalid IPv4 address: %s", addr)
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

// poolIndexToIP constructs an IP address from a pool index
// For IPv4: directly converts uint32 to 4-byte address
// For IPv6: combines the pool's prefix with the index as the lower 32 bits
func (ueIPPool *UeIPPool) poolIndexToIP(index uint32) net.IP {
	if ueIPPool.isIPv6 {
		// For IPv6, combine the network prefix with the pool index
		// Copy the base prefix and set the lower 32 bits to the index
		ip := make(net.IP, 16)
		copy(ip, ueIPPool.ueSubNet.IP.To16())
		// Set the last 4 bytes (lower 32 bits) to the pool index
		binary.BigEndian.PutUint32(ip[12:16], index)
		return ip
	}
	// For IPv4, direct conversion
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, index)
	return buf
}

func (ueIPPool *UeIPPool) Release(addr net.IP) {
	// Use helper function to extract pool index from IP address
	addrVal := ueIPPool.ipToPoolIndex(addr)
	res := ueIPPool.pool.Free(int(addrVal))
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
		firstAddr := ueIPPool.poolIndexToIP(uint32(element[0]))
		lastAddr := ueIPPool.poolIndexToIP(uint32(element[1]))
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
// For IPv6, we use a simplified approach: manage the lower 32 bits of the IID
// This provides a pool of ~4 billion addresses within a /64 prefix
// NOTE: Multiple IPv6 pools with different prefixes will have the same numeric range,
// but they represent different actual IP addresses (different prefix parts)
func calcIPv6AddrRange(ipNet *net.IPNet, uePrefixLength int) (minAddr, maxAddr uint32, err error) {
	// For IPv6, we typically allocate from a /64 or similar prefix
	// We use the lower 32 bits for pool management (sufficient for most deployments)
	// Full range: 0 to 2^32-1 (excluding network/broadcast equivalent for compatibility)

	ones, _ := ipNet.Mask.Size()

	if ones >= 64 {
		// For /64 or smaller, use a subset of the IID space
		// Avoid ::0 and ::ffff:ffff for safety
		minAddr = 1
		maxAddr = 0xFFFFFFFE
	} else {
		// For larger prefixes like /48, use full 32-bit range
		minAddr = 0
		maxAddr = 0xFFFFFFFF
	}

	logger.InitLog.Debugf("WNC: IPv6 pool range: %d to %d (prefix: /%d, UE prefix: /%d)",
		minAddr, maxAddr, ones, uePrefixLength)

	return minAddr, maxAddr, nil
}
