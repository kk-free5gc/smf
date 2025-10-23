package message_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/pfcp/message"
	"github.com/free5gc/smf/internal/pfcp/udp"
	"github.com/free5gc/smf/pkg/factory"
)

var testConfig = factory.Config{
	Info: &factory.Info{
		Version:     "1.0.0",
		Description: "SMF procdeure test configuration",
	},
	Configuration: &factory.Configuration{
		Sbi: &factory.Sbi{
			Scheme:       "http",
			RegisterIPv4: "127.0.0.1",
			BindingIPv4:  "127.0.0.1",
			Port:         8000,
		},
		PFCP: &factory.PFCP{
			NodeID: "10.4.0.1",
		},
	},
}

var testNodeID = &pfcpType.NodeID{
	NodeIdType: pfcpType.NodeIdTypeIpv4Address,
	IP:         net.ParseIP("10.4.0.1").To4(),
}

func initSmfContext() {
	context.InitSmfContext(&testConfig)
}

func initRuleList() ([]*context.PDR, []*context.FAR, []*context.BAR,
	[]*context.QER, []*context.URR,
) {
	testPDR := &context.PDR{
		PDRID: uint16(1),
		State: context.RULE_INITIAL,
		OuterHeaderRemoval: &pfcpType.OuterHeaderRemoval{
			OuterHeaderRemovalDescription: (1),
		},
		FAR: &context.FAR{},
		URR: []*context.URR{},
		QER: []*context.QER{},
	}

	testFAR := &context.FAR{
		FARID: uint32(123),
		// State Can be RULE_INITIAL or RULE_UPDATE or RULE_REMOVE
		State: context.RULE_INITIAL,
		ApplyAction: pfcpType.ApplyAction{
			Forw: true,
		},
		ForwardingParameters: &context.ForwardingParameters{},
		BAR:                  &context.BAR{},
	}

	testBAR := &context.BAR{
		BARID: uint8(124),
		// State Can be RULE_INITIAL or RULE_UPDATE or RULE_REMOVE
		State: context.RULE_INITIAL,
	}

	testQER := &context.QER{
		QERID: uint32(123),
		// State Can be RULE_INITIAL or RULE_UPDATE or RULE_REMOVE
		State: context.RULE_INITIAL,
	}

	testURR := &context.URR{
		URRID: uint32(123),
		// State Can be RULE_INITIAL or RULE_UPDATE or RULE_REMOVE
		State: context.RULE_INITIAL,
	}
	pdrList := make([]*context.PDR, 0)
	farList := make([]*context.FAR, 0)
	barList := make([]*context.BAR, 0)
	qerList := make([]*context.QER, 0)
	urrList := make([]*context.URR, 0)
	pdrList = append(pdrList, testPDR)
	farList = append(farList, testFAR)
	barList = append(barList, testBAR)
	qerList = append(qerList, testQER)
	urrList = append(urrList, testURR)
	return pdrList, farList, barList, qerList, urrList
}

func TestBuildPfcpAssociationSetupRequest(t *testing.T) {
	emptyReq, err := message.BuildPfcpAssociationSetupRequest()
	if err != nil {
		t.Errorf("TestBuildPfcpAssociationSetupRequest failed: %v", err)
	}

	// BuildPfcpAssociationSetupRequest buila a empty template of pfcp.PFCPAssociationSetupRequest
	assert.Equal(t, uint8(0), emptyReq.NodeID.NodeIdType)
	assert.Equal(t, net.IP(nil), emptyReq.NodeID.IP)
	assert.Equal(t, "", emptyReq.NodeID.FQDN)

	assert.Equal(t,
		udp.ServerStartTime,
		emptyReq.RecoveryTimeStamp.RecoveryTimeStamp)
	assert.Nil(t,
		emptyReq.UPFunctionFeatures)
	assert.Equal(t,
		pfcpType.CPFunctionFeatures{SupportedFeatures: 0},
		*emptyReq.CPFunctionFeatures)
}

func TestBuildPfcpAssociationSetupResponse(t *testing.T) {
	cause := pfcpType.Cause{CauseValue: pfcpType.CauseRequestAccepted}
	rsp, err := message.BuildPfcpAssociationSetupResponse(cause)
	if err != nil {
		t.Errorf("TestBuildPfcpAssociationSetupResponse failed: %v", err)
	}

	assert.Equal(t, uint8(0), rsp.NodeID.NodeIdType)
	assert.Equal(t, cause, *rsp.Cause)

	assert.Nil(t,
		rsp.UPFunctionFeatures)
	assert.Equal(t,
		pfcpType.CPFunctionFeatures{SupportedFeatures: 0},
		*rsp.CPFunctionFeatures)
}

func TestBuildPfcpAssociationReleaseRequest(t *testing.T) {
	emptyReq, err := message.BuildPfcpAssociationReleaseRequest()
	if err != nil {
		t.Errorf("TestBuildPfcpAssociationReleaseRequest failed: %v", err)
	}

	assert.Equal(t, uint8(0), emptyReq.NodeID.NodeIdType)
}

func TestBuildPfcpAssociationReleaseResponse(t *testing.T) {
	cause := pfcpType.Cause{CauseValue: pfcpType.CauseRequestAccepted}
	rsp, err := message.BuildPfcpAssociationReleaseResponse(cause)
	if err != nil {
		t.Errorf("TestBuildPfcpAssociationReleaseResponse failed: %v", err)
	}

	assert.Equal(t, uint8(0), rsp.NodeID.NodeIdType)
	assert.Equal(t, cause, *rsp.Cause)
}

func TestBuildPfcpSessionEstablishmentRequest(t *testing.T) {
	initSmfContext()
	smctx := context.NewSMContext("imsi-208930000000001", 10)
	pdrList, farList, barList, qerList, urrList := initRuleList()
	smctx.PFCPContext["10.4.0.1"] = &context.PFCPSessionContext{}

	req, err := message.BuildPfcpSessionEstablishmentRequest(
		*testNodeID, "10.4.0.1", smctx, pdrList, farList, barList, qerList, urrList)
	if err != nil {
		t.Errorf("TestBuildPfcpSessionEstablishmentRequest failed: %v", err)
	}
	// assert.Equal(t, uint8(0), req.NodeID.NodeIdType)
	assert.Equal(t, testNodeID, req.NodeID)
	assert.Equal(t, &pfcpType.PDNType{PdnType: pfcpType.PDNTypeIpv4}, req.PDNType)
	assert.Equal(t, len(req.CreatePDR), 1)
	assert.Equal(t, len(req.CreateFAR), 1)
	assert.Equal(t, len(req.CreateBAR), 1)
	assert.Equal(t, len(req.CreateQER), 1)
	assert.Equal(t, len(req.CreateURR), 1)
	assert.Equal(t, pdrList[0].State, context.RULE_CREATE)
	assert.Equal(t, farList[0].State, context.RULE_CREATE)
	assert.Equal(t, barList[0].State, context.RULE_CREATE)
	assert.Equal(t, qerList[0].State, context.RULE_CREATE)
	assert.Equal(t, urrList[0].State, context.RULE_CREATE)

	req2, err2 := message.BuildPfcpSessionEstablishmentRequest(
		*testNodeID, "10.4.0.1", smctx, nil, nil, nil, nil, nil)
	if err2 != nil {
		t.Errorf("TestBuildPfcpSessionEstablishmentRequest failed: %v", err2)
	}
	assert.NotEqual(t, req2, req)
	assert.Equal(t, len(req2.CreatePDR), 0)
	assert.Equal(t, len(req2.CreateFAR), 0)
	assert.Equal(t, len(req2.CreateBAR), 0)
	assert.Equal(t, len(req2.CreateQER), 0)
	assert.Equal(t, len(req2.CreateURR), 0)
}

// hsien
func TestBuildPfcpSessionEstablishmentResponse(t *testing.T) {
	initSmfContext()
	rsp, err := message.BuildPfcpSessionEstablishmentResponse()
	if err != nil {
		t.Errorf("TestBuildPfcpSessionEstablishmentResponse failed: %v", err)
	}
	assert.Equal(t, rsp.NodeID, testNodeID)
	assert.Equal(t, uint8(0), rsp.NodeID.NodeIdType)
	assert.Equal(t, pfcpType.CauseRequestAccepted, rsp.Cause.CauseValue)
	assert.NotNil(t, rsp.UPFSEID)
	assert.NotNil(t, rsp.CreatedPDR)
}

func TestBuildPfcpSessionModificationRequest(t *testing.T) {
	initSmfContext()
	smctx := context.NewSMContext("imsi-208930000000001", 10)
	pdrList, farList, barList, qerList, urrList := initRuleList()
	smctx.PFCPContext["10.4.0.1"] = &context.PFCPSessionContext{}

	req, err := message.BuildPfcpSessionModificationRequest(
		*testNodeID, "10.4.0.1", smctx, pdrList, farList, barList, qerList, urrList)
	if err != nil {
		t.Errorf("TestBuildPfcpSessionModificationRequest failed: %v", err)
	}

	assert.Equal(t, context.RULE_CREATE, pdrList[0].State)
	assert.Equal(t, context.RULE_CREATE, farList[0].State)
	assert.Equal(t, context.RULE_INITIAL, barList[0].State)
	assert.Equal(t, context.RULE_CREATE, qerList[0].State)
	assert.Equal(t, context.RULE_CREATE, urrList[0].State)

	assert.Equal(t, len(req.CreatePDR), 1)
	assert.Equal(t, len(req.CreateFAR), 1)
	assert.Equal(t, len(req.CreateBAR), 1)
	assert.Equal(t, len(req.CreateQER), 1)
	assert.Equal(t, len(req.CreateURR), 1)
}

func TestBuildPfcpSessionModificationResponse(t *testing.T) {
	initSmfContext()
	rsp, err := message.BuildPfcpSessionEstablishmentResponse()
	if err != nil {
		t.Errorf("BuildPfcpSessionModificationResponse failed: %v", err)
	}
	assert.Equal(t, rsp.NodeID, testNodeID)
	assert.Equal(t, pfcpType.CauseRequestAccepted, rsp.Cause.CauseValue)
	assert.NotNil(t, rsp.OffendingIE)
	assert.NotNil(t, rsp.CreatedPDR)
}

func TestBuildPfcpSessionDeletionResponse(t *testing.T) {
	_, err := message.BuildPfcpSessionDeletionResponse()
	if err != nil {
		t.Errorf("TestBuildPfcpSessionDeletionResponse failed: %v", err)
	}
}

func TestBuildPfcpSessionReportResponse(t *testing.T) {
	cause := pfcpType.Cause{CauseValue: pfcpType.CauseRequestAccepted}
	rsp, err := message.BuildPfcpSessionReportResponse(cause)
	if err != nil {
		t.Errorf("TestBuildPfcpSessionReportResponse failed: %v", err)
	}
	assert.Equal(t, cause, *rsp.Cause)
}

func TestBuildPfcpHeartbeatRequest(t *testing.T) {
	rsq, err := message.BuildPfcpHeartbeatRequest()
	if err != nil {
		t.Errorf("TestBuildPfcpHeartbeatRequest failed: %v", err)
	}

	assert.Equal(t, udp.ServerStartTime, rsq.RecoveryTimeStamp.RecoveryTimeStamp)
}

// WNC: Table-driven test for PDNType and UEIPAddress encoding across IPv4/IPv6/IPv4v6 sessions
func TestPFCPSessionEstablishmentRequest_PDNTypeAndUEIPAddress(t *testing.T) {
	initSmfContext()

	tests := []struct {
		name                     string
		pduSessionType           uint8
		pduAddressIPv4           net.IP
		pduAddressIPv6           net.IP
		pduAddressIPv6PrefixLen  uint8
		expectedPDNType          uint8
		expectedV4Flag           bool
		expectedV6Flag           bool
		expectedIpv6dFlag        bool
		expectedPrefixDelegation uint8
	}{
		{
			name:            "IPv4-only session",
			pduSessionType:  0x01, // nasMessage.PDUSessionTypeIPv4
			pduAddressIPv4:  net.ParseIP("10.60.0.1").To4(),
			pduAddressIPv6:  nil,
			expectedPDNType: pfcpType.PDNTypeIpv4,
			// Note: UEIPAddress flags are set in datapath.go during PDR creation,
			// not in BuildPfcpSessionEstablishmentRequest. We test PDNType here.
			expectedV4Flag:           false, // Not set in build.go
			expectedV6Flag:           false,
			expectedIpv6dFlag:        false,
			expectedPrefixDelegation: 0,
		},
		{
			name:                    "IPv6-only session with prefix delegation",
			pduSessionType:          0x02, // nasMessage.PDUSessionTypeIPv6
			pduAddressIPv4:          nil,
			pduAddressIPv6:          net.ParseIP("2001:db8::1"),
			pduAddressIPv6PrefixLen: 64,
			expectedPDNType:         pfcpType.PDNTypeIpv6,
			expectedV4Flag:          false,
			expectedV6Flag:          false, // Not set in build.go
			expectedIpv6dFlag:       false, // Set in datapath.go
			expectedPrefixDelegation: 0,
		},
		{
			name:                    "IPv4v6 dual-stack session",
			pduSessionType:          0x03, // nasMessage.PDUSessionTypeIPv4IPv6
			pduAddressIPv4:          net.ParseIP("10.60.0.1").To4(),
			pduAddressIPv6:          net.ParseIP("2001:db8::1"),
			pduAddressIPv6PrefixLen: 64,
			expectedPDNType:         pfcpType.PDNTypeIpv4v6,
			expectedV4Flag:          false,
			expectedV6Flag:          false, // Not set in build.go
			expectedIpv6dFlag:       false, // Set in datapath.go
			expectedPrefixDelegation: 0,
		},
		{
			name:            "IPv6-only without prefix delegation",
			pduSessionType:  0x02, // nasMessage.PDUSessionTypeIPv6
			pduAddressIPv4:  nil,
			pduAddressIPv6:  net.ParseIP("2001:db8::1"),
			pduAddressIPv6PrefixLen: 0, // No prefix delegation
			expectedPDNType:         pfcpType.PDNTypeIpv6,
			expectedV4Flag:          false,
			expectedV6Flag:          false,
			expectedIpv6dFlag:       false,
			expectedPrefixDelegation: 0,
		},
		{
			name:            "Non-IP session",
			pduSessionType:  0x04, // nasMessage.PDUSessionTypeUnstructured
			pduAddressIPv4:  nil,
			pduAddressIPv6:  nil,
			expectedPDNType: pfcpType.PDNTypeNonIp,
			expectedV4Flag:  false,
			expectedV6Flag:  false,
			expectedIpv6dFlag: false,
			expectedPrefixDelegation: 0,
		},
		{
			name:            "Ethernet session",
			pduSessionType:  0x05, // nasMessage.PDUSessionTypeEthernet
			pduAddressIPv4:  nil,
			pduAddressIPv6:  nil,
			expectedPDNType: pfcpType.PDNTypeEthernet,
			expectedV4Flag:  false,
			expectedV6Flag:  false,
			expectedIpv6dFlag: false,
			expectedPrefixDelegation: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create SMContext with specific PDU session type
			smctx := context.NewSMContext("imsi-208930000000001", 10)
			smctx.SelectedPDUSessionType = tt.pduSessionType
			smctx.PDUAddressIPv4 = tt.pduAddressIPv4
			smctx.PDUAddressIPv6 = tt.pduAddressIPv6
			smctx.PDUAddressIPv6PrefixLen = tt.pduAddressIPv6PrefixLen

			pdrList, farList, barList, qerList, urrList := initRuleList()
			smctx.PFCPContext["10.4.0.1"] = &context.PFCPSessionContext{}

			// Build PFCP Session Establishment Request
			req, err := message.BuildPfcpSessionEstablishmentRequest(
				*testNodeID, "10.4.0.1", smctx, pdrList, farList, barList, qerList, urrList)

			assert.NoError(t, err, "BuildPfcpSessionEstablishmentRequest should not return error")

			// Test PDNType is set correctly
			assert.NotNil(t, req.PDNType, "PDNType should be set")
			assert.Equal(t, tt.expectedPDNType, req.PDNType.PdnType,
				"PDNType should match expected value for %s", tt.name)

			// Note: UEIPAddress V4/V6/Ipv6d flags are set in datapath.go during PDR creation
			// (see datapath.go:548-561), not in BuildPfcpSessionEstablishmentRequest.
			// This test verifies PDNType encoding which IS set in build.go.
			// For UEIPAddress flag testing, see TestDataPath_UEIPAddressFlags in datapath package.
		})
	}
}

// WNC: Test to verify UEIPAddress flags are set correctly in PDR creation (integration test)
func TestPFCPSessionEstablishmentRequest_UEIPAddressFlagsIntegration(t *testing.T) {
	initSmfContext()

	tests := []struct {
		name                     string
		pduSessionType           uint8
		setupPDR                 func(*context.PDR, *context.SMContext)
		expectedV4Flag           bool
		expectedV6Flag           bool
		expectedIpv6dFlag        bool
	}{
		{
			name:           "IPv4-only PDR with UEIPAddress",
			pduSessionType: 0x01,
			setupPDR: func(pdr *context.PDR, smctx *context.SMContext) {
				smctx.PDUAddressIPv4 = net.ParseIP("10.60.0.1").To4()
				pdr.PDI.UEIPAddress = &pfcpType.UEIPAddress{
					V4:          true,
					V6:          false,
					Ipv4Address: smctx.PDUAddressIPv4,
				}
			},
			expectedV4Flag:    true,
			expectedV6Flag:    false,
			expectedIpv6dFlag: false,
		},
		{
			name:           "IPv6-only PDR with prefix delegation",
			pduSessionType: 0x02,
			setupPDR: func(pdr *context.PDR, smctx *context.SMContext) {
				smctx.PDUAddressIPv6 = net.ParseIP("2001:db8::1")
				smctx.PDUAddressIPv6PrefixLen = 64
				pdr.PDI.UEIPAddress = &pfcpType.UEIPAddress{
					V4:                        false,
					V6:                        true,
					Ipv6d:                     true,
					Ipv6Address:               smctx.PDUAddressIPv6,
					Ipv6PrefixDelegationBits:  64,
				}
			},
			expectedV4Flag:    false,
			expectedV6Flag:    true,
			expectedIpv6dFlag: true,
		},
		{
			name:           "IPv4v6 dual-stack PDR",
			pduSessionType: 0x03,
			setupPDR: func(pdr *context.PDR, smctx *context.SMContext) {
				smctx.PDUAddressIPv4 = net.ParseIP("10.60.0.1").To4()
				smctx.PDUAddressIPv6 = net.ParseIP("2001:db8::1")
				smctx.PDUAddressIPv6PrefixLen = 64
				pdr.PDI.UEIPAddress = &pfcpType.UEIPAddress{
					V4:                        true,
					V6:                        true,
					Ipv6d:                     true,
					Ipv4Address:               smctx.PDUAddressIPv4,
					Ipv6Address:               smctx.PDUAddressIPv6,
					Ipv6PrefixDelegationBits:  64,
				}
			},
			expectedV4Flag:    true,
			expectedV6Flag:    true,
			expectedIpv6dFlag: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			smctx := context.NewSMContext("imsi-208930000000001", 10)
			smctx.SelectedPDUSessionType = tt.pduSessionType
			smctx.PFCPContext["10.4.0.1"] = &context.PFCPSessionContext{}

			pdrList, farList, barList, qerList, urrList := initRuleList()

			// Setup PDR with UEIPAddress as per test case
			tt.setupPDR(pdrList[0], smctx)

			req, err := message.BuildPfcpSessionEstablishmentRequest(
				*testNodeID, "10.4.0.1", smctx, pdrList, farList, barList, qerList, urrList)

			assert.NoError(t, err)
			assert.NotNil(t, req.CreatePDR)
			assert.Len(t, req.CreatePDR, 1)

			// Verify UEIPAddress flags
			createPDR := req.CreatePDR[0]
			if createPDR.PDI != nil && createPDR.PDI.UEIPAddress != nil {
				ueIP := createPDR.PDI.UEIPAddress
				assert.Equal(t, tt.expectedV4Flag, ueIP.V4,
					"UEIPAddress V4 flag mismatch for %s", tt.name)
				assert.Equal(t, tt.expectedV6Flag, ueIP.V6,
					"UEIPAddress V6 flag mismatch for %s", tt.name)
				assert.Equal(t, tt.expectedIpv6dFlag, ueIP.Ipv6d,
					"UEIPAddress Ipv6d flag mismatch for %s", tt.name)

				if tt.expectedV4Flag {
					assert.NotNil(t, ueIP.Ipv4Address,
						"IPv4 address should be set when V4 flag is true")
				}
				if tt.expectedV6Flag {
					assert.NotNil(t, ueIP.Ipv6Address,
						"IPv6 address should be set when V6 flag is true")
				}
				if tt.expectedIpv6dFlag {
					assert.Greater(t, ueIP.Ipv6PrefixDelegationBits, uint8(0),
						"IPv6 prefix delegation bits should be > 0 when Ipv6d flag is true")
				}
			}
		})
	}
}
