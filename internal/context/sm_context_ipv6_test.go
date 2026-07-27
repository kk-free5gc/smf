package context

import (
	"net"
	"testing"

	"github.com/free5gc/smf/pkg/factory"
)

// WNC: TestRAPrefixTracksUniqueAllocation verifies that after the unique-/64
// allocator change, the RA prefix derived for each UE (GetIPv6PrefixFromAddress
// at /64, as used by the SM context / RA builder) equals that UE's allocated
// address masked to /64, and that two UEs get DISTINCT /64 prefixes. This is the
// SMF-side guarantee that the RA advertises each session's own unique /64.
func TestRAPrefixTracksUniqueAllocation(t *testing.T) {
	p := NewUEIPv6Pool(&factory.UEIPv6Pool{Prefix: "2001:db8:122::/48", UePrefixLength: 64})
	if p == nil {
		t.Fatal("NewUEIPv6Pool returned nil")
	}

	a1 := p.Allocate(nil)
	a2 := p.Allocate(nil)
	if a1 == nil || a2 == nil {
		t.Fatalf("allocation failed: a1=%v a2=%v", a1, a2)
	}

	// The RA prefix (derived exactly as sm_context.go does, at /64) must equal
	// the allocated address masked to /64.
	for _, a := range []net.IP{a1, a2} {
		raPrefix := GetIPv6PrefixFromAddress(a, 64)
		want := a.Mask(net.CIDRMask(64, 128))
		if !raPrefix.Equal(want) {
			t.Errorf("RA prefix %s != address /64 %s (addr %s)", raPrefix, want, a)
		}
	}

	// The two UEs must advertise DIFFERENT /64 prefixes.
	pfx1 := GetIPv6PrefixFromAddress(a1, 64)
	pfx2 := GetIPv6PrefixFromAddress(a2, 64)
	if pfx1.Equal(pfx2) {
		t.Errorf("expected distinct /64 prefixes, both were %s", pfx1)
	}
	if pfx1.String() != "2001:db8:122:1::" || pfx2.String() != "2001:db8:122:2::" {
		t.Errorf("unexpected prefixes: pfx1=%s pfx2=%s (want 2001:db8:122:1:: and :2::)", pfx1, pfx2)
	}
}

// TestDeriveIPv6FromPrefix verifies that deriveIPv6FromPrefix generates valid
// UE IPv6 addresses from prefix-only configurations that can be successfully
// allocated by the pool (avoiding the all-zero IID issue).
func TestDeriveIPv6FromPrefix(t *testing.T) {
	tests := []struct {
		name           string
		prefix         string
		expectedIPStr  string
		expectedIID    uint64 // Expected interface identifier value
	}{
		{
			name:          "/64 prefix should use IID=1",
			prefix:        "2001:db8::/64",
			expectedIPStr: "2001:db8::1",
			expectedIID:   1,
		},
		{
			name:          "/80 prefix should use IID=1 in host bits",
			prefix:        "2001:db8:1234:5678::/80",
			expectedIPStr: "2001:db8:1234:5678::1",
			expectedIID:   1,
		},
		{
			name:          "/127 prefix should use IID=0 (only 2 addresses)",
			prefix:        "2001:db8::fe/127",
			expectedIPStr: "2001:db8::fe",
			expectedIID:   0,
		},
		{
			name:          "/128 prefix should use IID=0 (single address)",
			prefix:        "2001:db8::100/128",
			expectedIPStr: "2001:db8::100",
			expectedIID:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipv6Net, err := net.ParseCIDR(tt.prefix)
			if err != nil {
				t.Fatalf("Failed to parse CIDR %s: %v", tt.prefix, err)
			}

			result := deriveIPv6FromPrefix(ipv6Net)
			if result == nil {
				t.Fatal("deriveIPv6FromPrefix returned nil")
			}

			if result.String() != tt.expectedIPStr {
				t.Errorf("Expected IP %s, got %s", tt.expectedIPStr, result.String())
			}
		})
	}
}

// TestDeriveIPv6FromPrefixNil verifies nil handling
func TestDeriveIPv6FromPrefixNil(t *testing.T) {
	result := deriveIPv6FromPrefix(nil)
	if result != nil {
		t.Errorf("Expected nil result for nil input, got %v", result)
	}
}

// TestStaticIPv6PrefixAllocation simulates the full flow of static prefix allocation
func TestStaticIPv6PrefixAllocation(t *testing.T) {
	// Parse a typical /64 static prefix configuration
	prefix := "2001:db8:abcd::/64"
	_, ipv6Net, err := net.ParseCIDR(prefix)
	if err != nil {
		t.Fatalf("Failed to parse prefix: %v", err)
	}

	// Derive the UE address (what the fix does in sm_context.go)
	derivedIP := deriveIPv6FromPrefix(ipv6Net)
	if derivedIP == nil {
		t.Fatal("Failed to derive IPv6 from prefix")
	}

	// Expected behavior: derived IP should NOT be the network address (all-zero IID)
	if derivedIP.Equal(ipv6Net.IP) {
		t.Errorf("Derived IP %s is equal to network address %s (should differ)",
			derivedIP, ipv6Net.IP)
	}

	// Expected: derived IP should be the first valid address (IID=1 for /64)
	expectedIP := "2001:db8:abcd::1"
	if derivedIP.String() != expectedIP {
		t.Errorf("Expected derived IP %s, got %s", expectedIP, derivedIP.String())
	}

	// Verify the IP is within the prefix subnet
	if !ipv6Net.Contains(derivedIP) {
		t.Errorf("Derived IP %s is not within prefix %s", derivedIP, ipv6Net.String())
	}

	// Simulate pool allocation check: convert to pool index
	// For /64, the IID portion should be 1 (not 0)
	ip16 := derivedIP.To16()
	iidValue := uint64(ip16[15]) // Last byte should be 1

	if iidValue != 1 {
		t.Errorf("Expected IID last byte to be 1, got %d", iidValue)
	}
}

// TestStaticIPv6PrefixAllocationEdgeCases tests edge cases
func TestStaticIPv6PrefixAllocationEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		prefix        string
		shouldUseZero bool // Whether index 0 is valid for this prefix length
	}{
		{
			name:          "/64 should NOT use index 0",
			prefix:        "2001:db8::/64",
			shouldUseZero: false,
		},
		{
			name:          "/80 should NOT use index 0",
			prefix:        "2001:db8:1234:5678::/80",
			shouldUseZero: false,
		},
		{
			name:          "/127 SHOULD use index 0 (only 2 addresses)",
			prefix:        "2001:db8::fe/127",
			shouldUseZero: true,
		},
		{
			name:          "/128 SHOULD use index 0 (single address)",
			prefix:        "2001:db8::100/128",
			shouldUseZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipv6Net, err := net.ParseCIDR(tt.prefix)
			if err != nil {
				t.Fatalf("Failed to parse prefix: %v", err)
			}

			derivedIP := deriveIPv6FromPrefix(ipv6Net)
			if derivedIP == nil {
				t.Fatal("Failed to derive IPv6")
			}

			isNetworkAddr := derivedIP.Equal(ipv6Net.IP)

			if tt.shouldUseZero && !isNetworkAddr {
				t.Errorf("For %s, expected to use network address (index 0), but got %s",
					tt.prefix, derivedIP)
			}

			if !tt.shouldUseZero && isNetworkAddr {
				t.Errorf("For %s, expected NOT to use network address (index 0), but got %s",
					tt.prefix, derivedIP)
			}
		})
	}
}
