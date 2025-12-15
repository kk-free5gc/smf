package context

import (
	"testing"
)

// TestDeriveDownlinkFlow tests the deriveDownlinkFlow function with various flow patterns
func TestDeriveDownlinkFlow(t *testing.T) {
	tests := []struct {
		name     string
		ulFlow   string
		expected string
	}{
		{
			name:     "wildcard assigned to any",
			ulFlow:   "permit out ip from assigned to any",
			expected: "permit out ip from any to assigned",
		},
		{
			name:     "wildcard any to assigned",
			ulFlow:   "permit out ip from any to assigned",
			expected: "permit out ip from assigned to any",
		},
		{
			name:     "specific CIDR to CIDR",
			ulFlow:   "permit out ip from 192.168.0.21 to 10.60.0.0/16",
			expected: "permit out ip from 10.60.0.0/16 to 192.168.0.21",
		},
		{
			name:     "CIDR to assigned",
			ulFlow:   "permit out ip from 10.60.0.0/16 to assigned",
			expected: "permit out ip from assigned to 10.60.0.0/16",
		},
		{
			name:     "assigned to CIDR",
			ulFlow:   "permit out ip from assigned to 10.60.0.0/16",
			expected: "permit out ip from 10.60.0.0/16 to assigned",
		},
		{
			name:     "with source port",
			ulFlow:   "permit out ip from any 80 to assigned",
			expected: "permit out ip from assigned to any 80",
		},
		{
			name:     "with destination port",
			ulFlow:   "permit out ip from assigned to any 443",
			expected: "permit out ip from any 443 to assigned",
		},
		{
			name:     "with both ports",
			ulFlow:   "permit out ip from assigned 8080 to any 443",
			expected: "permit out ip from any 443 to assigned 8080",
		},
		{
			name:     "with port range",
			ulFlow:   "permit out ip from assigned 1024-65535 to any",
			expected: "permit out ip from any to assigned 1024-65535",
		},
		{
			name:     "IPv6 CIDR",
			ulFlow:   "permit out ip from 2001:db8::/32 to assigned",
			expected: "permit out ip from assigned to 2001:db8::/32",
		},
		{
			name:     "complex with multiple ports",
			ulFlow:   "permit out ip from 192.168.1.0/24 80,443 to 10.0.0.0/8 8080",
			expected: "permit out ip from 10.0.0.0/8 8080 to 192.168.1.0/24 80,443",
		},
		{
			name:     "TCP protocol",
			ulFlow:   "permit out 6 from assigned to any",
			expected: "permit out 6 from any to assigned",
		},
		{
			name:     "UDP protocol with ports",
			ulFlow:   "permit out 17 from assigned 53 to any",
			expected: "permit out 17 from any to assigned 53",
		},
		{
			name:     "invalid - too few tokens",
			ulFlow:   "permit out ip from assigned",
			expected: "permit out ip from assigned", // Should return unchanged
		},
		{
			name:     "invalid - missing from keyword",
			ulFlow:   "permit out ip assigned to any",
			expected: "permit out ip assigned to any", // Should return unchanged
		},
		{
			name:     "invalid - missing to keyword",
			ulFlow:   "permit out ip from assigned any",
			expected: "permit out ip from assigned any", // Should return unchanged
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deriveDownlinkFlow(tt.ulFlow)
			if result != tt.expected {
				t.Errorf("deriveDownlinkFlow(%q) = %q, want %q", tt.ulFlow, result, tt.expected)
			}
		})
	}
}

// TestDeriveDownlinkFlowBidirectional tests that deriving DL from UL and then UL from DL returns the original
func TestDeriveDownlinkFlowBidirectional(t *testing.T) {
	tests := []string{
		"permit out ip from assigned to any",
		"permit out ip from 192.168.0.21 to 10.60.0.0/16",
		"permit out ip from any 80 to assigned",
		"permit out ip from assigned 8080 to any 443",
		"permit out 6 from 10.0.0.0/8 to assigned",
	}

	for _, ulFlow := range tests {
		t.Run(ulFlow, func(t *testing.T) {
			// Derive DL from UL
			dlFlow := deriveDownlinkFlow(ulFlow)

			// Derive UL back from DL
			ulFlowReversed := deriveDownlinkFlow(dlFlow)

			// Should get back the original UL flow
			if ulFlowReversed != ulFlow {
				t.Errorf("Bidirectional test failed:\n  Original UL: %q\n  Derived DL:  %q\n  Reversed UL: %q",
					ulFlow, dlFlow, ulFlowReversed)
			}
		})
	}
}
