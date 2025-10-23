package context

import (
	"net"
	"testing"

	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/smf/pkg/factory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WNC: Phase 2 - Unit tests for IPv6 and dual-stack UE IP allocation

func TestNewUEIPv6Pool(t *testing.T) {
	t.Run("Valid IPv6 Pool /48", func(t *testing.T) {
		factoryPool := &factory.UEIPv6Pool{
			Prefix:          "2001:db8::/48",
			UePrefixLength:  64,
		}

		pool := NewUEIPv6Pool(factoryPool)
		require.NotNil(t, pool, "IPv6 pool creation should succeed")
		assert.True(t, pool.isIPv6, "Pool should be marked as IPv6")
		assert.NotNil(t, pool.factoryIPv6Pool, "Factory config should be stored")
		assert.Equal(t, "2001:db8::/48", pool.ueSubNet.String())
	})

	t.Run("Valid IPv6 Pool /64", func(t *testing.T) {
		factoryPool := &factory.UEIPv6Pool{
			Prefix:          "2001:db8:1234::/64",
			UePrefixLength:  64,
		}

		pool := NewUEIPv6Pool(factoryPool)
		require.NotNil(t, pool, "IPv6 pool creation should succeed")
		assert.True(t, pool.isIPv6)
	})

	t.Run("Invalid IPv6 Prefix", func(t *testing.T) {
		factoryPool := &factory.UEIPv6Pool{
			Prefix:          "invalid-prefix",
			UePrefixLength:  64,
		}

		pool := NewUEIPv6Pool(factoryPool)
		assert.Nil(t, pool, "Invalid prefix should return nil")
	})
}

func TestIPv6PoolAllocation(t *testing.T) {
	factoryPool := &factory.UEIPv6Pool{
		Prefix:          "2001:db8::/64",
		UePrefixLength:  64,
	}

	pool := NewUEIPv6Pool(factoryPool)
	require.NotNil(t, pool)

	t.Run("Allocate First IPv6 Address", func(t *testing.T) {
		addr := pool.Allocate(nil)
		require.NotNil(t, addr, "Allocation should succeed")
		assert.True(t, pool.ueSubNet.Contains(addr), "Allocated address should be in pool subnet")
		assert.Nil(t, addr.To4(), "Address should be IPv6")
	})

	t.Run("Allocate Multiple IPv6 Addresses", func(t *testing.T) {
		addresses := make([]net.IP, 10)
		for i := 0; i < 10; i++ {
			addr := pool.Allocate(nil)
			require.NotNil(t, addr, "Allocation %d should succeed", i)
			addresses[i] = addr
		}

		// Verify all addresses are unique
		seen := make(map[string]bool)
		for _, addr := range addresses {
			key := addr.String()
			assert.False(t, seen[key], "Address %s should be unique", key)
			seen[key] = true
		}
	})

	t.Run("Release and Reallocate IPv6 Address", func(t *testing.T) {
		addr := pool.Allocate(nil)
		require.NotNil(t, addr)

		pool.Release(addr)

		// Should be able to allocate the same address again
		addr2 := pool.Allocate(addr)
		assert.Equal(t, addr.String(), addr2.String(), "Should allocate the same released address")
	})
}

func TestIPv6PoolSpecificAllocation(t *testing.T) {
	factoryPool := &factory.UEIPv6Pool{
		Prefix:          "2001:db8:abcd::/64",
		UePrefixLength:  64,
	}

	pool := NewUEIPv6Pool(factoryPool)
	require.NotNil(t, pool)

	t.Run("Allocate Specific IPv6 Address", func(t *testing.T) {
		requestedAddr := net.ParseIP("2001:db8:abcd::1234")
		require.NotNil(t, requestedAddr)

		addr := pool.Allocate(requestedAddr)
		require.NotNil(t, addr, "Specific allocation should succeed")
		assert.Equal(t, requestedAddr.String(), addr.String(), "Should allocate requested address")
	})

	t.Run("Allocate Already Used Address", func(t *testing.T) {
		requestedAddr := net.ParseIP("2001:db8:abcd::5678")

		addr1 := pool.Allocate(requestedAddr)
		require.NotNil(t, addr1)

		addr2 := pool.Allocate(requestedAddr)
		assert.Nil(t, addr2, "Should not allocate already-used address")
	})
}

func TestDualStackAllocation(t *testing.T) {
	// Setup mock UPI with dual-stack pools
	factoryIPv4Pool := &factory.UEIPPool{
		Cidr: "10.60.0.0/16",
	}
	factoryIPv6Pool := &factory.UEIPv6Pool{
		Prefix:         "2001:db8::/48",
		UePrefixLength: 64,
	}

	ipv4Pool := NewUEIPPool(factoryIPv4Pool)
	ipv6Pool := NewUEIPv6Pool(factoryIPv6Pool)

	require.NotNil(t, ipv4Pool)
	require.NotNil(t, ipv6Pool)

	t.Run("Allocate IPv4 and IPv6 Separately", func(t *testing.T) {
		ipv4Addr := ipv4Pool.Allocate(nil)
		ipv6Addr := ipv6Pool.Allocate(nil)

		require.NotNil(t, ipv4Addr, "IPv4 allocation should succeed")
		require.NotNil(t, ipv6Addr, "IPv6 allocation should succeed")

		assert.NotNil(t, ipv4Addr.To4(), "Should be IPv4 address")
		assert.Nil(t, ipv6Addr.To4(), "Should be IPv6 address")
	})

	t.Run("Release Dual-Stack Addresses", func(t *testing.T) {
		ipv4Addr := ipv4Pool.Allocate(nil)
		ipv6Addr := ipv6Pool.Allocate(nil)

		ipv4Pool.Release(ipv4Addr)
		ipv6Pool.Release(ipv6Addr)

		// Should be able to reallocate
		ipv4Addr2 := ipv4Pool.Allocate(ipv4Addr)
		ipv6Addr2 := ipv6Pool.Allocate(ipv6Addr)

		assert.Equal(t, ipv4Addr.String(), ipv4Addr2.String())
		assert.Equal(t, ipv6Addr.String(), ipv6Addr2.String())
	})
}

func TestIPv6PoolOverlap(t *testing.T) {
	t.Run("No Overlap - Different Prefixes", func(t *testing.T) {
		pool1 := NewUEIPv6Pool(&factory.UEIPv6Pool{
			Prefix:         "2001:db8:1::/64",
			UePrefixLength: 64,
		})
		pool2 := NewUEIPv6Pool(&factory.UEIPv6Pool{
			Prefix:         "2001:db8:2::/64",
			UePrefixLength: 64,
		})

		require.NotNil(t, pool1)
		require.NotNil(t, pool2)

		pools := []*UeIPPool{pool1, pool2}
		assert.False(t, isOverlap(pools), "Different IPv6 prefixes should not overlap")
	})

	t.Run("IPv4 and IPv6 Pools No Overlap", func(t *testing.T) {
		ipv4Pool := NewUEIPPool(&factory.UEIPPool{Cidr: "10.60.0.0/16"})
		ipv6Pool := NewUEIPv6Pool(&factory.UEIPv6Pool{
			Prefix:         "2001:db8::/48",
			UePrefixLength: 64,
		})

		require.NotNil(t, ipv4Pool)
		require.NotNil(t, ipv6Pool)

		pools := []*UeIPPool{ipv4Pool, ipv6Pool}
		assert.False(t, isOverlap(pools), "IPv4 and IPv6 pools should not overlap")
	})
}

func TestUEIPAllocationResult(t *testing.T) {
	t.Run("IPv4-Only Result", func(t *testing.T) {
		result := &UEIPAllocationResult{
			IPv4Address:     net.ParseIP("10.60.0.1"),
			UseStaticIPv4:   false,
			AllocatedFamily: nasMessage.PDUSessionTypeIPv4,
		}

		assert.NotNil(t, result.IPv4Address)
		assert.Nil(t, result.IPv6Address)
		assert.Equal(t, nasMessage.PDUSessionTypeIPv4, result.AllocatedFamily)
	})

	t.Run("IPv6-Only Result", func(t *testing.T) {
		result := &UEIPAllocationResult{
			IPv6Address:     net.ParseIP("2001:db8::1"),
			UseStaticIPv6:   false,
			AllocatedFamily: nasMessage.PDUSessionTypeIPv6,
		}

		assert.Nil(t, result.IPv4Address)
		assert.NotNil(t, result.IPv6Address)
		assert.Equal(t, nasMessage.PDUSessionTypeIPv6, result.AllocatedFamily)
	})

	t.Run("Dual-Stack Result", func(t *testing.T) {
		result := &UEIPAllocationResult{
			IPv4Address:     net.ParseIP("10.60.0.1"),
			IPv6Address:     net.ParseIP("2001:db8::1"),
			UseStaticIPv4:   false,
			UseStaticIPv6:   false,
			AllocatedFamily: nasMessage.PDUSessionTypeIPv4IPv6,
		}

		assert.NotNil(t, result.IPv4Address)
		assert.NotNil(t, result.IPv6Address)
		assert.Equal(t, nasMessage.PDUSessionTypeIPv4IPv6, result.AllocatedFamily)
	})
}

func TestSMContextPDUAddressHelpers(t *testing.T) {
	smContext := &SMContext{}

	t.Run("HasPDUIPv4 and HasPDUIPv6", func(t *testing.T) {
		// Initially no addresses
		assert.False(t, smContext.HasPDUIPv4())
		assert.False(t, smContext.HasPDUIPv6())

		// Add IPv4
		smContext.PDUAddressIPv4 = net.ParseIP("10.60.0.1")
		assert.True(t, smContext.HasPDUIPv4())
		assert.False(t, smContext.HasPDUIPv6())

		// Add IPv6
		smContext.PDUAddressIPv6 = net.ParseIP("2001:db8::1")
		assert.True(t, smContext.HasPDUIPv4())
		assert.True(t, smContext.HasPDUIPv6())
		assert.True(t, smContext.IsDualStack())
	})

	t.Run("PDUIPv4String and PDUIPv6String", func(t *testing.T) {
		smContext.PDUAddressIPv4 = net.ParseIP("10.60.0.1")
		smContext.PDUAddressIPv6 = net.ParseIP("2001:db8::1")

		ipv4Str, ok := smContext.PDUIPv4String()
		assert.True(t, ok)
		assert.Equal(t, "10.60.0.1", ipv4Str)

		ipv6Str, ok := smContext.PDUIPv6String()
		assert.True(t, ok)
		assert.Equal(t, "2001:db8::1", ipv6Str)
	})

	t.Run("GetPDUAddressByFamily", func(t *testing.T) {
		smContext.PDUAddressIPv4 = net.ParseIP("10.60.0.1")
		smContext.PDUAddressIPv6 = net.ParseIP("2001:db8::1")

		ipv4, ok := smContext.GetPDUAddressByFamily(false)
		assert.True(t, ok)
		assert.Equal(t, "10.60.0.1", ipv4.String())

		ipv6, ok := smContext.GetPDUAddressByFamily(true)
		assert.True(t, ok)
		assert.Equal(t, "2001:db8::1", ipv6.String())
	})

	t.Run("IsIPSession", func(t *testing.T) {
		smContext.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4
		assert.True(t, smContext.IsIPSession())

		smContext.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv6
		assert.True(t, smContext.IsIPSession())

		smContext.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4IPv6
		assert.True(t, smContext.IsIPSession())

		smContext.SelectedPDUSessionType = nasMessage.PDUSessionTypeEthernet
		assert.False(t, smContext.IsIPSession())

		smContext.SelectedPDUSessionType = nasMessage.PDUSessionTypeUnstructured
		assert.False(t, smContext.IsIPSession())
	})
}

func TestPDUAddressToNAS(t *testing.T) {
	t.Run("IPv4-Only NAS Encoding", func(t *testing.T) {
		smContext := &SMContext{
			SelectedPDUSessionType: nasMessage.PDUSessionTypeIPv4,
			PDUAddressIPv4:         net.ParseIP("10.60.0.1").To4(),
		}

		addr, addrLen := smContext.PDUAddressToNAS()
		assert.Equal(t, uint8(5), addrLen, "IPv4 address should be 4 bytes + 1 byte type")
		assert.Equal(t, byte(10), addr[0])
		assert.Equal(t, byte(60), addr[1])
		assert.Equal(t, byte(0), addr[2])
		assert.Equal(t, byte(1), addr[3])
	})

	t.Run("IPv6-Only NAS Encoding", func(t *testing.T) {
		smContext := &SMContext{
			SelectedPDUSessionType: nasMessage.PDUSessionTypeIPv6,
			PDUAddressIPv6:         net.ParseIP("2001:db8::1234"),
		}

		addr, addrLen := smContext.PDUAddressToNAS()
		assert.Equal(t, uint8(9), addrLen, "IPv6 IID should be 8 bytes + 1 byte type")
		// Last 8 bytes of 2001:db8::1234 are the interface identifier
		// In 2001:db8::1234, the last 8 bytes are 00 00 00 00 00 00 12 34
		assert.Equal(t, byte(0), addr[0])
		assert.Equal(t, byte(0), addr[1])
		assert.Equal(t, byte(0), addr[2])
		assert.Equal(t, byte(0), addr[3])
		assert.Equal(t, byte(0), addr[4])
		assert.Equal(t, byte(0), addr[5])
		assert.Equal(t, byte(0x12), addr[6])
		assert.Equal(t, byte(0x34), addr[7])
	})

	t.Run("Dual-Stack NAS Encoding", func(t *testing.T) {
		smContext := &SMContext{
			SelectedPDUSessionType: nasMessage.PDUSessionTypeIPv4IPv6,
			PDUAddressIPv4:         net.ParseIP("10.60.0.1").To4(),
			PDUAddressIPv6:         net.ParseIP("2001:db8::5678"),
		}

		addr, addrLen := smContext.PDUAddressToNAS()
		assert.Equal(t, uint8(13), addrLen, "Dual-stack should be 4 + 8 + 1 bytes")
		// First 4 bytes: IPv4
		assert.Equal(t, byte(10), addr[0])
		assert.Equal(t, byte(60), addr[1])
		// Bytes 4-11: IPv6 IID (last 8 bytes of IPv6 address)
		assert.Equal(t, byte(0x56), addr[10])
		assert.Equal(t, byte(0x78), addr[11])
	})
}
