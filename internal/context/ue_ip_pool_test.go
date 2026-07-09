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
