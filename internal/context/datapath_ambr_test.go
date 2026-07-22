package context

import (
	"testing"

	"github.com/free5gc/openapi/models"
)

// WNC: buildSessionAmbrMBR converts a session rule's AuthSessAmbr into a PFCP MBR.
// A nil AMBR must yield (nil, nil) so the caller skips the session-AMBR QER instead
// of dereferencing a nil pointer and panicking (observed when SM subscription data
// carries no sessionAmbr for the DNN).
func TestBuildSessionAmbrMBR(t *testing.T) {
	// nil AMBR -> no MBR, no error, no panic
	mbr, err := buildSessionAmbrMBR(nil)
	if err != nil {
		t.Fatalf("nil ambr: unexpected error %v", err)
	}
	if mbr != nil {
		t.Errorf("nil ambr: expected nil MBR, got %+v", mbr)
	}

	// valid AMBR -> converted MBR (1000 Mbps = 1_000_000 kbps, 500 Mbps = 500_000 kbps)
	mbr, err = buildSessionAmbrMBR(&models.Ambr{Uplink: "1000 Mbps", Downlink: "500 Mbps"})
	if err != nil {
		t.Fatalf("valid ambr: unexpected error %v", err)
	}
	if mbr == nil {
		t.Fatal("valid ambr: expected MBR, got nil")
	}
	if mbr.ULMBR != 1_000_000 {
		t.Errorf("ULMBR = %d, want 1000000", mbr.ULMBR)
	}
	if mbr.DLMBR != 500_000 {
		t.Errorf("DLMBR = %d, want 500000", mbr.DLMBR)
	}

	// missing bitrate unit -> error surfaced to caller
	if _, err := buildSessionAmbrMBR(&models.Ambr{Uplink: "1000", Downlink: "1000 Mbps"}); err == nil {
		t.Error("expected error for missing bitrate unit, got nil")
	}
}
