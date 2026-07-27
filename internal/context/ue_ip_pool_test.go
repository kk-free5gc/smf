package context_test

import (
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/pkg/factory"
)

func TestUeIPPool(t *testing.T) {
	ueIPPool := context.NewUEIPPool(&factory.UEIPPool{
		Cidr: "10.10.0.0/24",
	})

	require.NotNil(t, ueIPPool)

	var allocIP net.IP

	// make allowed ip pools
	var ipPoolList []net.IP
	for i := 0; i <= 255; i += 1 {
		ipStr := fmt.Sprintf("10.10.0.%d", i)
		ipPoolList = append(ipPoolList, net.ParseIP(ipStr).To4())
	}

	// allocate
	for i := 0; i < 256; i += 1 {
		allocIP = ueIPPool.Allocate(nil)
		require.Contains(t, ipPoolList, allocIP)
	}

	// ip pool is empty
	allocIP = ueIPPool.Allocate(nil)
	require.Nil(t, allocIP)

	// release IP
	for _, i := range rand.Perm(256) {
		ueIPPool.Release(ipPoolList[i])
	}

	// allocate specify ip
	for _, ip := range ipPoolList {
		allocIP = ueIPPool.Allocate(ip)
		require.Equal(t, ip, allocIP)
	}
}

func TestUeIPPool_ExcludeRange(t *testing.T) {
	ueIPPool := context.NewUEIPPool(&factory.UEIPPool{
		Cidr: "10.10.0.0/24",
	})

	require.Equal(t, uint64(0x0a0a0000), ueIPPool.Pool().Min())
	require.Equal(t, uint64(0x0a0a00FF), ueIPPool.Pool().Max())
	require.Equal(t, uint64(256), ueIPPool.Pool().Remain())

	excludeUeIPPool := context.NewUEIPPool(&factory.UEIPPool{
		Cidr: "10.10.0.0/28",
	})

	require.Equal(t, uint64(0x0a0a0000), excludeUeIPPool.Pool().Min())
	require.Equal(t, uint64(0x0a0a000F), excludeUeIPPool.Pool().Max())

	require.Equal(t, uint64(16), excludeUeIPPool.Pool().Remain())

	err := ueIPPool.Exclude(excludeUeIPPool)
	require.NoError(t, err)
	require.Equal(t, uint64(240), ueIPPool.Pool().Remain())

	for i := 16; i <= 255; i++ {
		allocate := ueIPPool.Allocate(nil)
		require.Equal(t, net.ParseIP(fmt.Sprintf("10.10.0.%d", i)).To4(), allocate)

		ueIPPool.Release(allocate)
	}
}

// WNC: verify the config `exclude:` field reserves addresses (e.g. a gateway) for both families.
func TestUeIPPool_ConfigExclude(t *testing.T) {
	// IPv4: reserve the gateway 10.10.0.1
	v4 := context.NewUEIPPool(&factory.UEIPPool{
		Cidr:    "10.10.0.0/24",
		Exclude: []string{"10.10.0.1"},
	})
	require.NotNil(t, v4)
	require.Equal(t, uint64(255), v4.Pool().Remain()) // 256 - 1 excluded

	gw := net.ParseIP("10.10.0.1").To4()
	for i := 0; i < 255; i++ {
		ip := v4.Allocate(nil)
		require.NotNil(t, ip)
		require.NotEqual(t, gw, ip) // the gateway is never handed out
	}
	require.Nil(t, v4.Allocate(nil)) // exhausted, gateway still reserved

	// IPv6: reserve the gateway ::1 (also keeps fe80::1 free for the router source LL)
	v6 := context.NewUEIPv6Pool(&factory.UEIPv6Pool{
		Prefix:         "2001:db8:155::/64",
		UePrefixLength: 64,
		Exclude:        []string{"2001:db8:155::1"},
	})
	require.NotNil(t, v6)
	// ::0 is excluded by the pool range and ::1 by config, so the first UE gets ::2
	require.Equal(t, net.ParseIP("2001:db8:155::2"), v6.Allocate(nil))
}

// WNC: Approach 2 — a dynamic pool (pool prefix shorter than UE prefix) allocates a
// UNIQUE /64 per UE by writing the allocation index into the subnet bits, with a
// fixed ::2 IID. Two UEs land in DIFFERENT /64s (the SLAAC downlink fix precondition).
func TestIPv6DynamicUniquePrefixAllocation(t *testing.T) {
	fp := &factory.UEIPv6Pool{Prefix: "2001:db8:122::/48", UePrefixLength: 64}
	p := context.NewUEIPv6Pool(fp)
	require.NotNil(t, p)

	// First dynamic allocation → subnet index 1 (index 0 reserved) → 2001:db8:122:1::2
	a1 := p.Allocate(nil)
	require.NotNil(t, a1)
	require.Equal(t, "2001:db8:122:1::2", a1.String())

	// Second dynamic allocation → subnet index 2 → 2001:db8:122:2::2
	a2 := p.Allocate(nil)
	require.NotNil(t, a2)
	require.Equal(t, "2001:db8:122:2::2", a2.String())

	// The two UEs are in DIFFERENT /64s.
	m := net.CIDRMask(64, 128)
	require.NotEqual(t, a1.Mask(m).String(), a2.Mask(m).String())
}

// WNC: A static /64 pool (pool prefix == UE prefix) keeps the OLD full-IID mapping,
// so operator-chosen static assignment IIDs (::10, ::11) survive byte-for-byte and
// two distinct static IIDs in the same /64 do not collide.
func TestIPv6StaticAssignmentRoundTripPreserved(t *testing.T) {
	fp := &factory.UEIPv6Pool{Prefix: "2001:db8:111:100::/64", UePrefixLength: 64}
	p := context.NewUEIPv6Pool(fp)
	require.NotNil(t, p)

	want := net.ParseIP("2001:db8:111:100::10")
	got := p.Allocate(want)
	require.NotNil(t, got)
	require.Equal(t, want.String(), got.String()) // full IID preserved, NOT rewritten to ::2

	want2 := net.ParseIP("2001:db8:111:100::11")
	got2 := p.Allocate(want2)
	require.NotNil(t, got2)
	require.Equal(t, want2.String(), got2.String())
}
