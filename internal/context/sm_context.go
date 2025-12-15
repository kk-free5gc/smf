package context

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/nas/nasConvert"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/smf/internal/logger"
	"github.com/free5gc/smf/pkg/factory"
	"github.com/free5gc/util/idgenerator"
)

var (
	smContextPool    sync.Map
	canonicalRef     sync.Map
	seidSMContextMap sync.Map
)

type DLForwardingType int

const (
	IndirectForwarding DLForwardingType = iota
	DirectForwarding
	NoForwarding
)

type UrrType int

// Reserved URR report for ID = 0 ~ 7
const (
	N3N6_MBQE_URR UrrType = iota
	N3N6_MAQE_URR
	N3N9_MBQE_URR
	N3N9_MAQE_URR
	N9N6_MBQE_URR
	N9N6_MAQE_URR
	RS_MONITOR_URR // WNC: Router Solicitation monitoring URR (independent of CHF)
	NOT_FOUND_URR
)

func (t UrrType) String() string {
	urrTypeList := []string{"N3N6_MBQE", "N3N6_MAQE", "N3N9_MBQE", "N3N9_MAQE", "N9N6_MBQE", "N9N6_MAQE", "RS_MONITOR"}
	if int(t) < len(urrTypeList) {
		return urrTypeList[t]
	}
	return "UNKNOWN"
}

func (t UrrType) IsBeforeQos() bool {
	urrTypeList := []bool{true, false, true, false, true, false, false} // WNC: RS_MONITOR_URR is after QoS
	if int(t) < len(urrTypeList) {
		return urrTypeList[t]
	}
	return false
}

func (t UrrType) Direct() string {
	urrTypeList := []string{"N3N6", "N3N6", "N3N9", "N3N9", "N9N6", "N9N6", "N3N6"} // WNC: RS_MONITOR_URR uses N3N6 path
	if int(t) < len(urrTypeList) {
		return urrTypeList[t]
	}
	return "UNKNOWN"
}

var smContextCount uint64

type SMContextState uint32

const (
	InActive SMContextState = iota
	ActivePending
	Active
	InActivePending
	ModificationPending
	PFCPModification
)

const DefaultPrecedence uint32 = 255

func init() {
}

func GetSMContextCount() uint64 {
	return atomic.AddUint64(&smContextCount, 1)
}

type EventExposureNotification struct {
	*models.NsmfEventExposureNotification

	Uri string
}

type UsageReport struct {
	UrrId uint32
	UpfId string

	TotalVolume    uint64
	UplinkVolume   uint64
	DownlinkVolume uint64

	TotalPktNum    uint64
	UplinkPktNum   uint64
	DownlinkPktNum uint64

	ReportTpye models.ChfConvergedChargingTriggerType
}

var TeidGenerator *idgenerator.IDGenerator

type SMContext struct {
	*models.SmfPduSessionSmContextCreateData

	Ref string

	LocalSEID  uint64
	RemoteSEID uint64

	UnauthenticatedSupi bool

	Pei          string
	Identifier   string
	PDUSessionID int32

	LocalULTeid uint32
	LocalDLTeid uint32

	UpCnxState models.UpCnxState

	HoState models.HoState

	SelectionParam          *UPFSelectionParams
	PDUAddress              net.IP // Legacy field - kept for backward compatibility, points to IPv4 for dual-stack
	PDUAddressIPv4          net.IP // WNC: IPv4 address for dual-stack support (Phase 2)
	PDUAddressIPv6          net.IP // WNC: IPv6 address for dual-stack support (Phase 2)
	PDUAddressIPv6PrefixLen uint8  // WNC: IPv6 delegated prefix length (e.g., 64 for /64) - required for PFCP and RA (Phase 2)
	PDUAddressIPv6LinkLocal net.IP // WNC: IPv6 link-local address (fe80::/64 + IID) for RS/RA/NS/NA/DAD support
	UseStaticIP             bool
	UseStaticIPv6           bool // WNC: Static IPv6 assignment flag (Phase 2)
	SelectedPDUSessionType  uint8

	DnnConfiguration models.DnnConfiguration

	SMPolicyID string

	// Handover related
	DLForwardingType         DLForwardingType
	DLDirectForwardingTunnel *ngapType.UPTransportLayerInformation
	IndirectForwardingTunnel *DataPath

	// UP Security support TS 29.502 R16 6.1.6.2.39
	UpSecurity                                                     *models.UpSecurity
	MaximumDataRatePerUEForUserPlaneIntegrityProtectionForUpLink   models.MaxIntegrityProtectedDataRate
	MaximumDataRatePerUEForUserPlaneIntegrityProtectionForDownLink models.MaxIntegrityProtectedDataRate
	// SMF verified UP security result of Xn-handover TS 33.501 6.6.1
	UpSecurityFromPathSwitchRequestSameAsLocalStored bool

	// Client
	CommunicationClientApiPrefix string

	AMFProfile         models.NrfNfDiscoveryNfProfile
	SelectedPCFProfile models.NrfNfDiscoveryNfProfile
	SelectedCHFProfile models.NrfNfDiscoveryNfProfile
	SmStatusNotifyUri  string

	Tunnel      *UPTunnel
	SelectedUPF *UPNode
	BPManager   *BPManager
	// NodeID(string form) to PFCP Session Context
	PFCPContext                         map[string]*PFCPSessionContext
	PDUSessionRelease_DUE_TO_DUP_PDU_ID bool

	DNNInfo *SnssaiSmfDnnInfo

	// WNC: Router Solicitation monitoring flag (persisted from DNN config)
	// This flag is set during session creation and persists regardless of SelectedUPF state
	// Avoids repeated config tree traversal and survives UPF pointer churn (handover, release, etc.)
	EnableRouterSolicitationMonitor bool

	// WNC: Default flow descriptions for catch-all PDRs (from DNN config or hardcoded fallback)
	// These are set during session creation and used when building default PCC rules
	DefaultUlFlow string // Uplink: "permit out ip from assigned to any"
	DefaultDlFlow string // Downlink: "permit out ip from any to assigned"

	// SM Policy related
	PCCRules            map[string]*PCCRule
	SessionRules        map[string]*SessionRule
	TrafficControlDatas map[string]*TrafficControlData
	ChargingData        map[string]*models.ChargingData
	QosDatas            map[string]*models.QosData

	UpPathChgEarlyNotification map[string]*EventExposureNotification // Key: Uri+NotifId
	UpPathChgLateNotification  map[string]*EventExposureNotification // Key: Uri+NotifId
	DataPathToBeRemoved        map[int64]*DataPath                   // Key: pathID

	SelectedSessionRuleID string

	// QoS
	defRuleID               uint8
	QoSRuleIDGenerator      *idgenerator.IDGenerator
	PacketFilterIDGenerator *idgenerator.IDGenerator
	QFIGenerator            *idgenerator.IDGenerator
	PCCRuleIDToQoSRuleID    map[string]uint8
	qosDataToQFI            map[string]uint8
	PacketFilterIDToNASPFID map[string]uint8
	AMBRQerMap              map[uuid.UUID]uint32
	QerUpfMap               map[string]uint32
	AdditonalQosFlows       map[uint8]*QoSFlow // Key: qfi

	// URR
	UrrIDGenerator     *idgenerator.IDGenerator
	UrrIdMap           map[UrrType]uint32
	UrrUpfMap          map[string]*URR
	UrrReportTime      time.Duration
	UrrReportThreshold uint64
	// Cache the usage reports, sent from UPF
	// Those information will be included in CDR.
	UrrReports []UsageReport

	// Charging Related
	ChargingDataRef string
	// Each PDU session has a unique charging id
	ChargingID    int32
	RequestedUnit int32
	// key = urrid
	// All urr can map to a rating group
	// However, a rating group may map to more than one urr
	// e.g. In UL CL case, the rating group for recoreding PDU Session volume may map to two URR
	//		one is for PSA 1, the other is for PSA 2.
	ChargingInfo map[uint32]*ChargingInfo
	// NAS
	Pti                     uint8
	EstAcceptCause5gSMValue uint8

	// PCO Related
	ProtocolConfigurationOptions *ProtocolConfigurationOptions

	// State
	state SMContextState

	UeCmRegistered bool

	// Loggers
	Log *logrus.Entry

	// 5GSM Timers
	// T3591 is PDU SESSION MODIFICATION COMMAND timer
	T3591 *Timer
	// T3592 is PDU SESSION RELEASE COMMAND timer
	T3592 *Timer

	// lock
	SMLock sync.Mutex
}

func GenerateTEID() (uint32, error) {
	var id uint32
	if tmpID, err := TeidGenerator.Allocate(); err != nil {
		return 0, err
	} else {
		id = uint32(tmpID)
	}

	return id, nil
}

func ReleaseTEID(teid uint32) {
	TeidGenerator.FreeID(int64(teid))
}

func canonicalName(id string, pduSessID int32) string {
	return fmt.Sprintf("%s-%d", id, pduSessID)
}

func ResolveRef(id string, pduSessID int32) (string, error) {
	if value, ok := canonicalRef.Load(canonicalName(id, pduSessID)); ok {
		ref := value.(string)
		return ref, nil
	} else {
		return "", fmt.Errorf("UE[%s] - PDUSessionID[%d] not found in SMContext", id, pduSessID)
	}
}

func NewSMContext(id string, pduSessID int32) *SMContext {
	smContext := new(SMContext)
	// Create Ref and identifier
	smContext.Ref = uuid.New().URN()
	smContextPool.Store(smContext.Ref, smContext)
	canonicalRef.Store(canonicalName(id, pduSessID), smContext.Ref)

	smContext.Log = logger.PduSessLog.WithFields(logrus.Fields{
		logger.FieldSupi:         id,
		logger.FieldPDUSessionID: fmt.Sprintf("%d", pduSessID),
	})

	smContext.SetState(InActive)
	smContext.Identifier = id
	smContext.PDUSessionID = pduSessID
	smContext.PFCPContext = make(map[string]*PFCPSessionContext)
	smContext.LocalSEID = GetSMContextCount()

	// initialize SM Policy Data
	smContext.PCCRules = make(map[string]*PCCRule)
	smContext.SessionRules = make(map[string]*SessionRule)
	smContext.TrafficControlDatas = make(map[string]*TrafficControlData)
	smContext.QosDatas = make(map[string]*models.QosData)
	smContext.UpPathChgEarlyNotification = make(map[string]*EventExposureNotification)
	smContext.UpPathChgLateNotification = make(map[string]*EventExposureNotification)
	smContext.DataPathToBeRemoved = make(map[int64]*DataPath)

	smContext.ProtocolConfigurationOptions = &ProtocolConfigurationOptions{}

	smContext.BPManager = NewBPManager(id)
	smContext.Tunnel = NewUPTunnel()

	smContext.QoSRuleIDGenerator = idgenerator.NewGenerator(1, 255)
	if defRuleID, err := smContext.QoSRuleIDGenerator.Allocate(); err != nil {
		logger.CtxLog.Warnln("Create Default QoS rule error ", err)
	} else {
		smContext.defRuleID = uint8(defRuleID)
	}

	smContext.PacketFilterIDGenerator = idgenerator.NewGenerator(1, 255)
	smContext.QFIGenerator = idgenerator.NewGenerator(2, 63) // 1 always reserve for default Qos
	smContext.PCCRuleIDToQoSRuleID = make(map[string]uint8)
	smContext.PacketFilterIDToNASPFID = make(map[string]uint8)
	smContext.qosDataToQFI = make(map[string]uint8)
	smContext.AMBRQerMap = make(map[uuid.UUID]uint32)
	smContext.QerUpfMap = make(map[string]uint32)
	smContext.AdditonalQosFlows = make(map[uint8]*QoSFlow)
	smContext.UrrIDGenerator = idgenerator.NewGenerator(1, math.MaxUint32)
	smContext.UrrIdMap = make(map[UrrType]uint32)
	smContext.GenerateUrrId()
	smContext.UrrUpfMap = make(map[string]*URR)

	smContext.ChargingInfo = make(map[uint32]*ChargingInfo)
	smContext.ChargingID = GenerateChargingID()

	if factory.SmfConfig != nil &&
		factory.SmfConfig.Configuration != nil {
		smContext.UrrReportTime = time.Duration(factory.SmfConfig.Configuration.UrrPeriod) * time.Second
		smContext.UrrReportThreshold = factory.SmfConfig.Configuration.UrrThreshold
		logger.CtxLog.Infof("UrrPeriod: %v", smContext.UrrReportTime)
		logger.CtxLog.Infof("UrrThreshold: %d", smContext.UrrReportThreshold)
		if factory.SmfConfig.Configuration.RequestedUnit != 0 {
			smContext.RequestedUnit = factory.SmfConfig.Configuration.RequestedUnit
		} else {
			smContext.RequestedUnit = 1000
		}
	}

	var err error
	smContext.LocalDLTeid, err = GenerateTEID()
	if err != nil {
		return nil
	}

	smContext.LocalULTeid, err = GenerateTEID()
	if err != nil {
		return nil
	}

	return smContext
}

// *** add unit test ***//
func GetSMContextByRef(ref string) *SMContext {
	var smCtx *SMContext
	if value, ok := smContextPool.Load(ref); ok {
		smCtx = value.(*SMContext)
	}
	return smCtx
}

func GetSMContextById(id string, pduSessID int32) *SMContext {
	var smCtx *SMContext
	ref, err := ResolveRef(id, pduSessID)
	if err != nil {
		return nil
	}
	if value, ok := smContextPool.Load(ref); ok {
		smCtx = value.(*SMContext)
	}
	return smCtx
}

// *** add unit test ***//
func RemoveSMContext(ref string) {
	var smContext *SMContext
	if value, ok := smContextPool.Load(ref); ok {
		smContext = value.(*SMContext)
	} else {
		return
	}

	// WNC: Release both IPv4 and IPv6 addresses (dual-stack support)
	if smContext.SelectedUPF != nil {
		upi := GetUserPlaneInformation()

		// Release IPv4 address
		if smContext.PDUAddressIPv4 != nil {
			logger.PduSessLog.Infof("WNC: UE[%s] PDUSessionID[%d] Release IPv4[%s]",
				smContext.Supi, smContext.PDUSessionID, smContext.PDUAddressIPv4.String())
			upi.ReleaseUEIP(smContext.SelectedUPF, smContext.PDUAddressIPv4, smContext.UseStaticIP)
		} else if smContext.PDUAddress != nil {
			// Fallback to legacy field for backward compatibility
			logger.PduSessLog.Infof("UE[%s] PDUSessionID[%d] Release IP[%s]",
				smContext.Supi, smContext.PDUSessionID, smContext.PDUAddress.String())
			upi.ReleaseUEIP(smContext.SelectedUPF, smContext.PDUAddress, smContext.UseStaticIP)
		}

		// Release IPv6 address
		if smContext.PDUAddressIPv6 != nil {
			logger.PduSessLog.Infof("WNC: UE[%s] PDUSessionID[%d] Release IPv6[%s]",
				smContext.Supi, smContext.PDUSessionID, smContext.PDUAddressIPv6.String())
			upi.ReleaseUEIP(smContext.SelectedUPF, smContext.PDUAddressIPv6, smContext.UseStaticIPv6)
		}

		smContext.SelectedUPF = nil
	}

	for _, pfcpSessionContext := range smContext.PFCPContext {
		seidSMContextMap.Delete(pfcpSessionContext.LocalSEID)
	}

	ReleaseTEID(smContext.LocalULTeid)
	ReleaseTEID(smContext.LocalDLTeid)

	smContextPool.Delete(ref)
	canonicalRef.Delete(canonicalName(smContext.Supi, smContext.PDUSessionID))
	smContext.Log.Infof("smContext[%s] is deleted from pool", ref)
}

// *** add unit test ***//
func GetSMContextBySEID(seid uint64) *SMContext {
	if value, ok := seidSMContextMap.Load(seid); ok {
		smContext := value.(*SMContext)
		return smContext
	}
	return nil
}

func (smContext *SMContext) GenerateUrrId() {
	if id, err := smContext.UrrIDGenerator.Allocate(); err == nil {
		smContext.UrrIdMap[N3N6_MBQE_URR] = uint32(id)
	}
	if id, err := smContext.UrrIDGenerator.Allocate(); err == nil {
		smContext.UrrIdMap[N3N6_MAQE_URR] = uint32(id)
	}
	if id, err := smContext.UrrIDGenerator.Allocate(); err == nil {
		smContext.UrrIdMap[N9N6_MBQE_URR] = uint32(id)
	}
	if id, err := smContext.UrrIDGenerator.Allocate(); err == nil {
		smContext.UrrIdMap[N9N6_MAQE_URR] = uint32(id)
	}
	if id, err := smContext.UrrIDGenerator.Allocate(); err == nil {
		smContext.UrrIdMap[N3N9_MBQE_URR] = uint32(id)
	}
	if id, err := smContext.UrrIDGenerator.Allocate(); err == nil {
		smContext.UrrIdMap[N3N9_MAQE_URR] = uint32(id)
	}
}

func (smContext *SMContext) BuildCreatedData() *models.SmfPduSessionSmContextCreatedData {
	return &models.SmfPduSessionSmContextCreatedData{
		SNssai: smContext.SNssai,
	}
}

func (smContext *SMContext) SetState(state SMContextState) {
	oldState := SMContextState(atomic.LoadUint32((*uint32)(&smContext.state)))

	atomic.StoreUint32((*uint32)(&smContext.state), uint32(state))
	smContext.Log.Tracef("State[%s] -> State[%s]", oldState, state)
}

func (smContext *SMContext) CheckState(state SMContextState) bool {
	curState := SMContextState(atomic.LoadUint32((*uint32)(&smContext.state)))
	check := curState == state
	if !check {
		smContext.Log.Warnf("Unexpected state, expect: [%s], actual:[%s]", state, curState)
	}
	return check
}

func (smContext *SMContext) State() SMContextState {
	return SMContextState(atomic.LoadUint32((*uint32)(&smContext.state)))
}

// IsIPSession returns true if this session uses IP addressing (IPv4, IPv6, or IPv4v6)
// WNC: Non-IP sessions (Ethernet, Unstructured) do not have PDU addresses
func (smContext *SMContext) IsIPSession() bool {
	return smContext.SelectedPDUSessionType == nasMessage.PDUSessionTypeIPv4 ||
		smContext.SelectedPDUSessionType == nasMessage.PDUSessionTypeIPv6 ||
		smContext.SelectedPDUSessionType == nasMessage.PDUSessionTypeIPv4IPv6
}

// HasPDUIPv4 returns true if session has an IPv4 address allocated
// WNC: Enhanced for dual-stack support (Phase 2)
func (smContext *SMContext) HasPDUIPv4() bool {
	// Prefer new dual-stack field, fallback to legacy field for backward compatibility
	if smContext.PDUAddressIPv4 != nil {
		return true
	}
	return smContext.PDUAddress != nil && smContext.PDUAddress.To4() != nil
}

// HasPDUIPv6 returns true if session has an IPv6 address allocated
// WNC: Enhanced for dual-stack support (Phase 2)
func (smContext *SMContext) HasPDUIPv6() bool {
	// Use new dual-stack field for IPv6
	return smContext.PDUAddressIPv6 != nil
}

// PDUIPv4String returns the IPv4 address as string, or ("", false) if not available
// WNC: Enhanced for dual-stack support (Phase 2)
func (smContext *SMContext) PDUIPv4String() (string, bool) {
	if !smContext.HasPDUIPv4() {
		return "", false
	}
	if smContext.PDUAddressIPv4 != nil {
		return smContext.PDUAddressIPv4.String(), true
	}
	return smContext.PDUAddress.To4().String(), true
}

// PDUIPv6String returns the IPv6 address as string, or ("", false) if not available
// WNC: Enhanced for dual-stack support (Phase 2)
func (smContext *SMContext) PDUIPv6String() (string, bool) {
	if !smContext.HasPDUIPv6() {
		return "", false
	}
	return smContext.PDUAddressIPv6.String(), true
}

// PDUIPv4 returns the IPv4 address, or (nil, false) if not available
// WNC: Enhanced for dual-stack support (Phase 2)
func (smContext *SMContext) PDUIPv4() (net.IP, bool) {
	if !smContext.HasPDUIPv4() {
		return nil, false
	}
	if smContext.PDUAddressIPv4 != nil {
		return smContext.PDUAddressIPv4, true
	}
	return smContext.PDUAddress.To4(), true
}

// PDUIPv6 returns the IPv6 address, or (nil, false) if not available
// WNC: New helper for dual-stack support (Phase 2)
func (smContext *SMContext) PDUIPv6() (net.IP, bool) {
	if !smContext.HasPDUIPv6() {
		return nil, false
	}
	return smContext.PDUAddressIPv6, true
}

// GetPDUAddressByFamily returns the IP address for the requested family
// WNC: New helper for dual-stack support (Phase 2)
func (smContext *SMContext) GetPDUAddressByFamily(isIPv6 bool) (net.IP, bool) {
	if isIPv6 {
		return smContext.PDUIPv6()
	}
	return smContext.PDUIPv4()
}

// IsDualStack returns true if both IPv4 and IPv6 addresses are allocated
// WNC: New helper for dual-stack support (Phase 2)
func (smContext *SMContext) IsDualStack() bool {
	return smContext.HasPDUIPv4() && smContext.HasPDUIPv6()
}

// PDUIPv6PrefixString returns the IPv6 prefix in CIDR notation (e.g., "2001:db8::/64")
// WNC: New helper for PCF interaction (Phase 2.6)
func (smContext *SMContext) PDUIPv6PrefixString() (string, bool) {
	if !smContext.HasPDUIPv6() {
		return "", false
	}

	// Extract network prefix from the IPv6 address
	ipv6Prefix := GetIPv6PrefixFromAddress(smContext.PDUAddressIPv6, smContext.PDUAddressIPv6PrefixLen)
	if ipv6Prefix == nil {
		return "", false
	}

	// Format as CIDR notation: "prefix/length"
	prefixStr := fmt.Sprintf("%s/%d", ipv6Prefix.String(), smContext.PDUAddressIPv6PrefixLen)
	return prefixStr, true
}

// ComputePDUIPv6LinkLocal computes the link-local IPv6 address (fe80::/64 + IID)
// from the global IPv6 address by reusing the lower 64 bits (Interface ID)
// WNC: New helper for RS/RA/NS/NA/DAD support
func (smContext *SMContext) ComputePDUIPv6LinkLocal() net.IP {
	if !smContext.HasPDUIPv6() {
		return nil
	}

	// IPv6 link-local prefix: fe80::/64
	linkLocal := make(net.IP, 16)
	linkLocal[0] = 0xfe
	linkLocal[1] = 0x80
	// Bytes 2-7 are zero (link-local prefix)

	// Copy the lower 64 bits (Interface ID) from the global address
	copy(linkLocal[8:], smContext.PDUAddressIPv6[8:])

	return linkLocal
}

// PDUIPv6LinkLocal returns the cached link-local IPv6 address, computing it if necessary
// WNC: New helper for RS/RA/NS/NA/DAD support
func (smContext *SMContext) PDUIPv6LinkLocal() (net.IP, bool) {
	if !smContext.HasPDUIPv6() {
		return nil, false
	}

	// Compute and cache if not already cached
	if smContext.PDUAddressIPv6LinkLocal == nil {
		smContext.PDUAddressIPv6LinkLocal = smContext.ComputePDUIPv6LinkLocal()
	}

	return smContext.PDUAddressIPv6LinkLocal, true
}

// HasPDUIPv6LinkLocal returns true if link-local IPv6 address is available
// WNC: New helper for RS/RA/NS/NA/DAD support
func (smContext *SMContext) HasPDUIPv6LinkLocal() bool {
	linkLocal, ok := smContext.PDUIPv6LinkLocal()
	return ok && linkLocal != nil
}

// PDUAddressToNAS converts PDU address(es) to NAS format
// WNC: Enhanced for dual-stack support (Phase 2)
func (smContext *SMContext) PDUAddressToNAS() ([12]byte, uint8) {
	var addr [12]byte
	var addrLen uint8

	switch smContext.SelectedPDUSessionType {
	case nasMessage.PDUSessionTypeIPv4:
		// IPv4 only: 4 bytes + 1 byte PDU session type
		if smContext.PDUAddressIPv4 != nil {
			copy(addr[:], smContext.PDUAddressIPv4.To4())
		} else if smContext.PDUAddress != nil {
			// Fallback to legacy field for backward compatibility
			copy(addr[:], smContext.PDUAddress.To4())
		}
		addrLen = 4 + 1

	case nasMessage.PDUSessionTypeIPv6:
		// IPv6 only: Interface identifier (8 bytes) + 1 byte PDU session type
		// 3GPP TS 24.501: For IPv6, only interface identifier is sent (last 8 bytes)
		if smContext.PDUAddressIPv6 != nil {
			// Copy last 8 bytes (interface identifier) of IPv6 address
			copy(addr[:8], smContext.PDUAddressIPv6[8:16])
		}
		addrLen = 8 + 1

	case nasMessage.PDUSessionTypeIPv4IPv6:
		// Dual-stack: IPv6 interface identifier (8 bytes) + IPv4 (4 bytes) + 1 byte PDU session type
		// 3GPP TS 24.501 9.11.4.11.1
		if smContext.PDUAddressIPv6 != nil {
			copy(addr[:8], smContext.PDUAddressIPv6[8:16])
		}
		if smContext.PDUAddressIPv4 != nil {
			copy(addr[8:12], smContext.PDUAddressIPv4.To4())
		} else if smContext.PDUAddress != nil {
			// Fallback to legacy field for IPv4
			copy(addr[8:12], smContext.PDUAddress.To4())
		}
		addrLen = 12 + 1
	}

	return addr, addrLen
}

func (smContext *SMContext) GetNodeIDByLocalSEID(seid uint64) pfcpType.NodeID {
	for _, pfcpCtx := range smContext.PFCPContext {
		if pfcpCtx.LocalSEID == seid {
			return pfcpCtx.NodeID
		}
	}

	return pfcpType.NodeID{}
}

func (smContext *SMContext) AllocateLocalSEIDForUPPath(path UPPath) {
	for _, upNode := range path {
		NodeIDtoIP := upNode.NodeID.ResolveNodeIdToIp().String()
		if _, exist := smContext.PFCPContext[NodeIDtoIP]; !exist {
			allocatedSEID := AllocateLocalSEID()

			// WNC: Populate IPv4 and IPv6 UE addresses for PFCP session
			var ueIPv4, ueIPv6 net.IP
			if ipv4, ok := smContext.PDUIPv4(); ok {
				ueIPv4 = ipv4
			}
			if ipv6, ok := smContext.PDUIPv6(); ok {
				ueIPv6 = ipv6
			}

			smContext.PFCPContext[NodeIDtoIP] = &PFCPSessionContext{
				PDRs:          make(map[uint16]*PDR),
				NodeID:        upNode.NodeID,
				LocalSEID:     allocatedSEID,
				UEIPv4Address: ueIPv4,
				UEIPv6Address: ueIPv6,
			}

			seidSMContextMap.Store(allocatedSEID, smContext)
		}
	}
}

func (smContext *SMContext) AllocateLocalSEIDForDataPath(dataPath *DataPath) {
	logger.PduSessLog.Traceln("In AllocateLocalSEIDForDataPath")
	for node := dataPath.FirstDPNode; node != nil; node = node.Next() {
		NodeIDtoIP := node.UPF.NodeID.ResolveNodeIdToIp().String()
		logger.PduSessLog.Traceln("NodeIDtoIP: ", NodeIDtoIP)
		if _, exist := smContext.PFCPContext[NodeIDtoIP]; !exist {
			allocatedSEID := AllocateLocalSEID()

			// WNC: Populate IPv4 and IPv6 UE addresses for PFCP session
			var ueIPv4, ueIPv6 net.IP
			if ipv4, ok := smContext.PDUIPv4(); ok {
				ueIPv4 = ipv4
			}
			if ipv6, ok := smContext.PDUIPv6(); ok {
				ueIPv6 = ipv6
			}

			smContext.PFCPContext[NodeIDtoIP] = &PFCPSessionContext{
				PDRs:          make(map[uint16]*PDR),
				NodeID:        node.UPF.NodeID,
				LocalSEID:     allocatedSEID,
				UEIPv4Address: ueIPv4,
				UEIPv6Address: ueIPv6,
			}

			seidSMContextMap.Store(allocatedSEID, smContext)
		}
	}
}

func (smContext *SMContext) PutPDRtoPFCPSession(nodeID pfcpType.NodeID, pdr *PDR) error {
	NodeIDtoIP := nodeID.ResolveNodeIdToIp().String()
	if pfcpSessCtx, exist := smContext.PFCPContext[NodeIDtoIP]; exist {
		smContext.Log.Tracef("PutPDRtoPFCPSession [%+v]", pdr)
		pfcpSessCtx.PDRs[pdr.PDRID] = pdr
	} else {
		return fmt.Errorf("Can't find PFCPContext[%s] to put PDR(%d)", NodeIDtoIP, pdr.PDRID)
	}
	return nil
}

// extractIPv6PrefixLength searches the UPF's IPv6 pools to find the pool containing
// the allocated IPv6 address and returns the delegated prefix length.
// WNC: Required for PFCP UEIPAddress IE and Router Advertisement (Phase 2)
func extractIPv6PrefixLength(upf *UPNode, ipv6Addr net.IP, dnn string, snssai *SNssai) uint8 {
	if upf == nil || upf.UPF == nil || ipv6Addr == nil {
		return 0
	}

	// Search through UPF's SNssai/DNN configuration to find the pool containing this IPv6 address
	for _, snssaiInfo := range upf.UPF.SNssaiInfos {
		if !snssaiInfo.SNssai.Equal(snssai) {
			continue
		}

		for _, dnnInfo := range snssaiInfo.DnnList {
			if dnnInfo.Dnn != dnn {
				continue
			}

			// Check dynamic IPv6 pools
			for _, pool := range dnnInfo.UeIPv6Pools {
				if pool.ueSubNet.Contains(ipv6Addr) && pool.factoryIPv6Pool != nil {
					logger.CtxLog.Debugf("WNC: Found IPv6 address %s in dynamic pool %s (UE prefix: /%d)",
						ipv6Addr, pool.ueSubNet.String(), pool.factoryIPv6Pool.UePrefixLength)
					return uint8(pool.factoryIPv6Pool.UePrefixLength)
				}
			}

			// Check static IPv6 pools
			for _, pool := range dnnInfo.StaticIPv6Pools {
				if pool.ueSubNet.Contains(ipv6Addr) && pool.factoryIPv6Pool != nil {
					logger.CtxLog.Debugf("WNC: Found IPv6 address %s in static pool %s (UE prefix: /%d)",
						ipv6Addr, pool.ueSubNet.String(), pool.factoryIPv6Pool.UePrefixLength)
					return uint8(pool.factoryIPv6Pool.UePrefixLength)
				}
			}

			// Check static assignments
			for _, assignment := range dnnInfo.IPv6StaticAssignments {
				assignedIP := net.ParseIP(assignment.Address)
				if assignedIP != nil && assignedIP.Equal(ipv6Addr) {
					logger.CtxLog.Debugf("WNC: Found IPv6 address %s in static assignment (prefix: /%d)",
						ipv6Addr, assignment.PrefixLength)
					return uint8(assignment.PrefixLength)
				}
			}
		}
	}

	logger.CtxLog.Warnf("WNC: Could not find IPv6 prefix length for address %s in UPF %s",
		ipv6Addr, upf.Name)
	return 0
}

// deriveIPv6FromPrefix derives a valid UE IPv6 address from a prefix by using the
// pool's minimum allowed index (typically 1 for /64 prefixes to avoid all-zero IID).
// This ensures static prefix-only configurations can be successfully allocated.
// WNC: Fix for static IPv6 prefix allocation issue
func deriveIPv6FromPrefix(ipv6Net *net.IPNet) net.IP {
	if ipv6Net == nil {
		return nil
	}

	prefixLen, _ := ipv6Net.Mask.Size()
	hostBits := 128 - prefixLen

	// Determine the minimum allowed index based on prefix length
	// This matches the logic in calcIPv6AddrRange (ue_ip_pool.go:301-323)
	var minIndex uint64
	if hostBits >= 64 {
		// For /64 or shorter prefixes, exclude all-zero IID (index 0)
		minIndex = 1
	} else if hostBits > 1 {
		// For prefixes longer than /64 but with multiple addresses (e.g., /80)
		// Still exclude all-zero host portion
		minIndex = 1
	} else {
		// For /127 or /128, use index 0 (only address or first of two)
		minIndex = 0
	}

	// Build the IPv6 address by combining prefix with the minimum allowed IID
	ip := make(net.IP, 16)
	copy(ip, ipv6Net.IP.To16())

	if prefixLen > 64 {
		// For prefixes longer than /64, only some bits of bytes 8-15 are host bits
		hostMask := uint64(0xFFFFFFFFFFFFFFFF) >> (64 - hostBits)
		networkPortion := binary.BigEndian.Uint64(ip[8:16])
		networkPortion = (networkPortion & ^hostMask) | (minIndex & hostMask)
		binary.BigEndian.PutUint64(ip[8:16], networkPortion)
	} else {
		// For /64 or shorter, the full 64-bit IID (bytes 8-15) is available
		binary.BigEndian.PutUint64(ip[8:16], minIndex)
	}

	return ip
}

// WNC: Enhanced for dual-stack support (Phase 2)
func (c *SMContext) findPSAandAllocUeIP(param *UPFSelectionParams) error {
	c.Log.Traceln("findPSAandAllocUeIP")
	if param == nil {
		return fmt.Errorf("UPFSelectionParams is nil")
	}

	// WNC: log both context + selection param view of PDU session type for debugging
	c.Log.Infof("WNC: findPSAandAllocUeIP - SelectedPDUSessionType=%s SelectionParamType=%s",
		NasSessionTypeToString(c.SelectedPDUSessionType),
		NasSessionTypeToString(param.SelectedPDUSessionType))

	upi := GetUserPlaneInformation()
	var result *UEIPAllocationResult

	if GetSelf().ULCLSupport && CheckUEHasPreConfig(c.Supi) {
		groupName := GetULCLGroupNameFromSUPI(c.Supi)
		preConfigPathPool := GetUEDefaultPathPool(groupName)
		if preConfigPathPool != nil {
			// ULCL path - now supports dual-stack allocation
			result = preConfigPathPool.SelectUPFAndAllocUEIPForULCL(upi, param)
			if result != nil {
				c.SelectedUPF = result.UPF
			}
		}
	} else {
		// Use new dual-stack allocation
		result = upi.SelectUPFAndAllocUEIPDualStack(param)
		if result != nil {
			c.SelectedUPF = result.UPF
		}
	}

	if result == nil || c.SelectedUPF == nil {
		return fmt.Errorf("WNC: fail to allocate UE IP, Selection Parameter: %s", param.String())
	}

	// WNC: Populate Router Solicitation monitoring flag from DNN configuration
	// This persists the flag in SMContext so it survives UPF pointer churn (handover, release, etc.)
	c.populateRouterSolicitationMonitorFlag()

	// WNC: Populate default flow descriptions from DNN configuration
	// This allows operators to override the catch-all PDR flow descriptions
	c.populateDefaultFlowDescriptions()

	// WNC: Handle IP allocation based on session type (Phase 2)
	switch c.SelectedPDUSessionType {
	case nasMessage.PDUSessionTypeIPv4:
		// IPv4-only session
		if result.IPv4Address != nil {
			c.PDUAddress = result.IPv4Address // Legacy field for backward compatibility
			c.PDUAddressIPv4 = result.IPv4Address
			c.UseStaticIP = result.UseStaticIPv4
			c.Log.Infof("WNC: Allocated IPv4 address [%s]", result.IPv4Address.String())
		} else if c.PDUAddressIPv4 == nil {
			return fmt.Errorf("WNC: fail to allocate IPv4 address, Selection Parameter: %s", param.String())
		}

	case nasMessage.PDUSessionTypeIPv6:
		// WNC: Preserve original static flag before allocation for proper release behavior
		wasStaticIPv6Requested := c.UseStaticIPv6

		// IPv6-only session
		if result.IPv6Address != nil {
			c.PDUAddressIPv6 = result.IPv6Address
			// WNC: Preserve original static flag to prevent incorrect release of static addresses
			// If IPv6 was requested as static (from subscription), keep that flag even if the
			// allocator result shows it as dynamic (e.g., static bind in a dynamic pool)
			if wasStaticIPv6Requested {
				c.UseStaticIPv6 = true
				c.Log.Infof("WNC: Preserved static IPv6 flag for IPv6-only session")
			} else {
				c.UseStaticIPv6 = result.UseStaticIPv6
			}
			c.Log.Infof("WNC: Allocated IPv6 address [%s]", result.IPv6Address.String())
			// WNC: Extract IPv6 prefix length from the selected UPF's pool configuration
			if c.SelectedUPF != nil {
				prefixLen := extractIPv6PrefixLength(c.SelectedUPF, result.IPv6Address, c.Dnn, c.SelectionParam.SNssai)
				if prefixLen > 0 {
					c.PDUAddressIPv6PrefixLen = prefixLen
					c.Log.Infof("WNC: Captured IPv6 prefix length: /%d", prefixLen)
				}
			}
		} else if c.PDUAddressIPv6 == nil {
			// Check if static IPv6 was pre-configured
			return fmt.Errorf("WNC: fail to allocate IPv6 address, Selection Parameter: %s", param.String())
		} else {
			c.Log.Infof("WNC: Using pre-configured static IPv6 address [%s]", c.PDUAddressIPv6.String())
			// WNC: For static IPv6, also extract prefix length
			if c.SelectedUPF != nil && c.PDUAddressIPv6PrefixLen == 0 {
				prefixLen := extractIPv6PrefixLength(c.SelectedUPF, c.PDUAddressIPv6, c.Dnn, c.SelectionParam.SNssai)
				if prefixLen > 0 {
					c.PDUAddressIPv6PrefixLen = prefixLen
					c.Log.Infof("WNC: Captured IPv6 prefix length for static address: /%d", prefixLen)
				}
			}
		}

	case nasMessage.PDUSessionTypeIPv4IPv6:
		// WNC: Preserve original static flags before allocation for proper release behavior
		wasStaticIPv6Requested := c.UseStaticIPv6

		// Dual-stack session - allocate both IPv4 and IPv6
		if result.IPv4Address != nil && result.IPv6Address != nil {
			// Perfect dual-stack allocation
			c.PDUAddress = result.IPv4Address // Legacy field points to IPv4
			c.PDUAddressIPv4 = result.IPv4Address
			c.PDUAddressIPv6 = result.IPv6Address
			c.UseStaticIP = result.UseStaticIPv4
			c.UseStaticIPv6 = result.UseStaticIPv6
			c.Log.Infof("WNC: Allocated dual-stack: IPv4=%s, IPv6=%s",
				result.IPv4Address.String(), result.IPv6Address.String())

			// WNC: Extract IPv6 prefix length for dual-stack
			if c.SelectedUPF != nil && c.PDUAddressIPv6PrefixLen == 0 {
				prefixLen := extractIPv6PrefixLength(c.SelectedUPF, result.IPv6Address, c.Dnn, c.SelectionParam.SNssai)
				if prefixLen > 0 {
					c.PDUAddressIPv6PrefixLen = prefixLen
					c.Log.Infof("WNC: Captured IPv6 prefix length for dual-stack: /%d", prefixLen)
				}
			}
		} else if result.IPv4Address != nil {
			// Downgrade to IPv4-only
			c.PDUAddress = result.IPv4Address
			c.PDUAddressIPv4 = result.IPv4Address
			c.UseStaticIP = result.UseStaticIPv4
			c.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4
			c.EstAcceptCause5gSMValue = nasMessage.Cause5GSMPDUSessionTypeIPv4OnlyAllowed
			// WNC: Clear stale IPv6 state to prevent dual-stack mismatch in PFCP messages
			c.PDUAddressIPv6 = nil
			c.UseStaticIPv6 = false
			c.PDUAddressIPv6PrefixLen = 0
			if c.SelectionParam != nil {
				c.SelectionParam.PDUAddressIPv6 = nil
				c.SelectionParam.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4
			}
			c.Log.Warnf("WNC: Dual-stack requested but only IPv4 available - downgraded to IPv4-only [%s]",
				result.IPv4Address.String())
		} else if result.IPv6Address != nil {
			// Downgrade to IPv6-only
			c.PDUAddressIPv6 = result.IPv6Address
			// WNC: Preserve original static flag to prevent incorrect release of static addresses
			// If IPv6 was requested as static (from subscription), keep that flag even if the
			// allocator result shows it as dynamic (e.g., static bind in a dynamic pool)
			if wasStaticIPv6Requested {
				c.UseStaticIPv6 = true
				c.Log.Infof("WNC: Preserved static IPv6 flag for dual-stack downgrade to IPv6-only")
			} else {
				c.UseStaticIPv6 = result.UseStaticIPv6
			}
			c.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv6
			c.EstAcceptCause5gSMValue = nasMessage.Cause5GSMPDUSessionTypeIPv6OnlyAllowed
			// WNC: Clear stale IPv4 state to prevent dual-stack mismatch in PFCP messages
			c.PDUAddress = nil
			c.PDUAddressIPv4 = nil
			c.UseStaticIP = false
			if c.SelectionParam != nil {
				c.SelectionParam.PDUAddress = nil
				c.SelectionParam.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv6
			}
			c.Log.Warnf("WNC: Dual-stack requested but only IPv6 available - downgraded to IPv6-only [%s]",
				result.IPv6Address.String())

			// Extract IPv6 prefix length
			if c.SelectedUPF != nil {
				prefixLen := extractIPv6PrefixLength(c.SelectedUPF, result.IPv6Address, c.Dnn, c.SelectionParam.SNssai)
				if prefixLen > 0 {
					c.PDUAddressIPv6PrefixLen = prefixLen
					c.Log.Infof("WNC: Captured IPv6 prefix length: /%d", prefixLen)
				}
			}
		} else if c.PDUAddressIPv6 != nil {
			// WNC: Dual-stack requested but allocator couldn't serve it - keep preconfigured static IPv6
			c.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv6
			c.EstAcceptCause5gSMValue = nasMessage.Cause5GSMPDUSessionTypeIPv6OnlyAllowed
			// WNC: Clear stale IPv4 state to prevent dual-stack mismatch in PFCP messages
			c.PDUAddress = nil
			c.PDUAddressIPv4 = nil
			c.UseStaticIP = false
			if c.SelectionParam != nil {
				c.SelectionParam.PDUAddress = nil
				c.SelectionParam.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv6
			}
			c.Log.Warnf("WNC: Dual-stack requested but allocator failed - using preconfigured static IPv6 [%s]",
				c.PDUAddressIPv6.String())

			// Extract IPv6 prefix length for static address
			if c.SelectedUPF != nil && c.PDUAddressIPv6PrefixLen == 0 {
				prefixLen := extractIPv6PrefixLength(c.SelectedUPF, c.PDUAddressIPv6, c.Dnn, c.SelectionParam.SNssai)
				if prefixLen > 0 {
					c.PDUAddressIPv6PrefixLen = prefixLen
					c.Log.Infof("WNC: Captured IPv6 prefix length for static address: /%d", prefixLen)
				}
			}
		} else {
			return fmt.Errorf("WNC: fail to allocate any address for dual-stack, Selection Parameter: %s", param.String())
		}

	default:
		return fmt.Errorf("WNC: unsupported PDU session type: 0x%02x", c.SelectedPDUSessionType)
	}

	// Final validation: ensure at least one IP family is allocated
	if c.PDUAddressIPv4 == nil && c.PDUAddressIPv6 == nil {
		return fmt.Errorf("WNC: fail to allocate any PDU address, Selection Parameter: %s", param.String())
	}

	return nil
}

func (c *SMContext) AllocUeIP() error {
	// Always populate SelectionParam for UPF selection
	c.SelectionParam = &UPFSelectionParams{
		Dnn: c.Dnn,
		SNssai: &SNssai{
			Sst: c.SNssai.Sst,
			Sd:  c.SNssai.Sd,
		},
		SelectedPDUSessionType: c.SelectedPDUSessionType,
		PDUAddressIPv6:         nil, // WNC: Will be set if static IPv6 is configured (Phase 2)
	}

	// WNC: log the session type that will drive pool selection
	c.Log.Infof("WNC: AllocUeIP - SelectedPDUSessionType=%s", NasSessionTypeToString(c.SelectedPDUSessionType))

	// Check for non-IP PDU session types (3GPP TS 23.501)
	// Ethernet and Unstructured sessions do not require UE IP addresses
	isNonIPSession := c.SelectedPDUSessionType == nasMessage.PDUSessionTypeEthernet ||
		c.SelectedPDUSessionType == nasMessage.PDUSessionTypeUnstructured

	if isNonIPSession {
		c.Log.Infof("WNC: Non-IP PDU session type (0x%02x): selecting UPF without IP allocation", c.SelectedPDUSessionType)
		// Still need to select UPF for data path setup, just skip IP allocation
		upi := GetUserPlaneInformation()
		if GetSelf().ULCLSupport && CheckUEHasPreConfig(c.Supi) {
			groupName := GetULCLGroupNameFromSUPI(c.Supi)
			preConfigPathPool := GetUEDefaultPathPool(groupName)
			if preConfigPathPool != nil {
				// For non-IP sessions, select UPF without allocating from IP pools
				selectedUPFName := preConfigPathPool.SelectUPFWithoutAllocUEIPForULCL(upi, c.SelectionParam)
				if selectedUPFName != "" {
					c.SelectedUPF = upi.UPFs[selectedUPFName]
				}
			}
		} else {
			// For non-IP sessions, select UPF without allocating from IP pools
			c.SelectedUPF = upi.SelectUPFWithoutAllocUEIP(c.SelectionParam)
		}
		if c.SelectedUPF == nil {
			return fmt.Errorf("WNC: failed to select UPF for non-IP session, Selection Parameter: %s",
				c.SelectionParam.String())
		}
		c.Log.Infof("WNC: Selected UPF [%s] for non-IP session (no IP allocated)", c.SelectedUPF.Name)
		// PDUAddress remains nil for non-IP sessions - this is expected
		return nil
	}

	// WNC: For IP sessions, handle static IP configuration (Phase 2)
	// Precedence: static bind > static pool > dynamic pool (per family)
	if len(c.DnnConfiguration.StaticIpAddress) > 0 {
		staticIPConfig := c.DnnConfiguration.StaticIpAddress[0]

		// Handle static IPv4 assignment
		if staticIPConfig.Ipv4Addr != "" {
			c.SelectionParam.PDUAddress = net.ParseIP(staticIPConfig.Ipv4Addr).To4()
			c.Log.Infof("WNC: Static IPv4 configured for selection: %s", staticIPConfig.Ipv4Addr)
		}

		// WNC: Handle static IPv6 assignment (Phase 2)
		// Note: IPv6 static addresses are pre-configured in SMContext before allocation
		if staticIPConfig.Ipv6Addr != "" {
			staticIPv6 := net.ParseIP(staticIPConfig.Ipv6Addr)
			if staticIPv6 != nil && staticIPv6.To4() == nil {
				// Pre-configure IPv6 address - will be validated against pools during allocation
				c.PDUAddressIPv6 = staticIPv6
				c.UseStaticIPv6 = true
				c.SelectionParam.PDUAddressIPv6 = staticIPv6 // WNC: Pass to allocator for validation
				c.Log.Infof("WNC: Static IPv6 pre-configured (will validate against pools): %s", staticIPConfig.Ipv6Addr)
			}
		}

		// WNC: Handle static IPv6 prefix (Phase 2)
		if staticIPConfig.Ipv6Prefix != "" {
			// IPv6 prefix will be used for interface identifier generation
			c.Log.Infof("WNC: Static IPv6 prefix configured: %s", staticIPConfig.Ipv6Prefix)
			// Parse and extract the prefix for later use
			_, ipv6Net, err := net.ParseCIDR(staticIPConfig.Ipv6Prefix)
			if err == nil && ipv6Net != nil {
				// Only set PDUAddressIPv6 from prefix if no explicit Ipv6Addr was configured
				// Otherwise we would overwrite the actual address with the network prefix
				if c.PDUAddressIPv6 == nil {
					// WNC: Derive a valid UE IPv6 address from the prefix
					// The pool excludes index 0 (all-zero IID) for /64 prefixes, so we use index 1
					// This ensures the allocator can successfully Use() the address
					derivedIPv6 := deriveIPv6FromPrefix(ipv6Net)
					c.PDUAddressIPv6 = derivedIPv6
					c.UseStaticIPv6 = true
					c.SelectionParam.PDUAddressIPv6 = derivedIPv6 // WNC: Pass derived address to allocator
					c.Log.Infof("WNC: Derived UE IPv6 address from prefix: %s", derivedIPv6)
				}
				// Always store the prefix length
				prefixLen, _ := ipv6Net.Mask.Size()
				c.PDUAddressIPv6PrefixLen = uint8(prefixLen)
				c.Log.Infof("WNC: Parsed IPv6 prefix length: /%d", prefixLen)
			} else {
				c.Log.Warnf("WNC: Failed to parse IPv6 prefix: %s - %v", staticIPConfig.Ipv6Prefix, err)
			}
		}
	}

	// For IP sessions, allocate IP address (or validate static assignment)
	if err := c.findPSAandAllocUeIP(c.SelectionParam); err != nil {
		return err
	}
	return nil
}

// This function create ULCL data paths.
func (c *SMContext) SelectULCLDataPaths() error {
	if c.SelectionParam == nil || c.SelectedUPF == nil {
		return fmt.Errorf("SelectULCLDataPath err: SelectionParam or SelectedUPF is nil")
	}

	if GetSelf().ULCLSupport && CheckUEHasPreConfig(c.Supi) {
		c.Log.Infof("Has pre-config ULCL paths")
		uePreConfigPaths := GetUEPreConfigPaths(c.Supi, c.SelectedUPF.Name)
		for _, dp := range uePreConfigPaths.DataPathPool {
			if !dp.IsDefaultPath {
				c.Tunnel.AddDataPath(dp)
			}
		}
	}
	return nil
}

// This function create a data path to be default data path.
func (c *SMContext) SelectDefaultDataPath() error {
	if c.SelectionParam == nil || c.SelectedUPF == nil {
		return fmt.Errorf("SelectDefaultDataPath err: SelectionParam or SelectedUPF is nil")
	}

	defaultPath := c.Tunnel.DataPathPool.GetDefaultPath()
	if defaultPath != nil {
		// A default path already exists.
		// Use this one.
		c.Log.Infof("Has default path")
		defaultPath = c.Tunnel.DataPathPool.GetDefaultPath()
	} else if GetSelf().ULCLSupport && CheckUEHasPreConfig(c.Supi) {
		// Fallback on pre-config default path
		c.Log.Infof("Has pre-config default path")
		uePreConfigPaths := GetUEPreConfigPaths(c.Supi, c.SelectedUPF.Name)
		defaultPath = uePreConfigPaths.DataPathPool.GetDefaultPath()
		c.Tunnel.AddDataPath(defaultPath)
	} else {
		// UE has no pre-config path and default path
		// Use default route
		c.Log.Infof("Has no pre-config route. Has no default path")
		defaultUPPath := GetUserPlaneInformation().GetDefaultUserPlanePathByDNNAndUPF(
			c.SelectionParam, c.SelectedUPF)
		defaultPath = GenerateDataPath(defaultUPPath)
		if defaultPath != nil {
			defaultPath.IsDefaultPath = true
			// WNC: Populate session type for IPv4/IPv6/dual-stack handling (Phase 2)
			defaultPath.PDUSessionType = c.SelectedPDUSessionType
			c.Tunnel.AddDataPath(defaultPath)
		}
	}

	if defaultPath == nil {
		return fmt.Errorf("data path not found, Selection Parameter: %s",
			c.SelectionParam.String())
	}

	if !defaultPath.Activated {
		defaultPath.ActivateTunnelAndPDR(c, DefaultPrecedence)
	}

	return nil
}

func (c *SMContext) CreatePccRuleDataPath(pccRule *PCCRule,
	tcData *TrafficControlData, qosData *models.QosData,
	chgData *models.ChargingData,
) error {
	var targetRoute models.RouteToLocation
	if tcData != nil && len(tcData.RouteToLocs) > 0 {
		targetRoute = *tcData.RouteToLocs[0]
	}
	param := &UPFSelectionParams{
		Dnn: c.Dnn,
		SNssai: &SNssai{
			Sst: c.SNssai.Sst,
			Sd:  c.SNssai.Sd,
		},
		Dnai:                   targetRoute.Dnai,
		SelectedPDUSessionType: c.SelectedPDUSessionType,
	}
	createdUpPath := GetUserPlaneInformation().GetDefaultUserPlanePathByDNN(param)
	createdDataPath := GenerateDataPath(createdUpPath)
	if createdDataPath == nil {
		return fmt.Errorf("fail to create data path for pcc rule[%s]", pccRule.PccRuleId)
	}
	// WNC: Populate session type for IPv4/IPv6/dual-stack handling (Phase 2)
	createdDataPath.PDUSessionType = c.SelectedPDUSessionType
	c.Log.Tracef("CreatePccRuleDataPath: pcc rule: %+v", pccRule)

	// Try to use a default pcc rule as default data path
	if c.Tunnel.DataPathPool.GetDefaultPath() == nil &&
		pccRule.Precedence == 255 {
		createdDataPath.IsDefaultPath = true
	}

	createdDataPath.GBRFlow = isGBRFlow(qosData)
	createdDataPath.ActivateTunnelAndPDR(c, uint32(pccRule.Precedence))
	c.Tunnel.AddDataPath(createdDataPath)
	pccRule.Datapath = createdDataPath
	pccRule.AddDataPathForwardingParameters(c, &targetRoute)

	if chgLevel, err := pccRule.IdentifyChargingLevel(); err != nil {
		c.Log.Warnf("fail to identify charging level[%+v] for pcc rule[%s]", err, pccRule.PccRuleId)
	} else {
		pccRule.Datapath.AddChargingRules(c, chgLevel, chgData)
	}

	if pccRule.RefQosDataID() != "" {
		pccRule.Datapath.AddQoS(c, pccRule.QFI, qosData)
		c.AddQosFlow(pccRule.QFI, qosData)
	}
	return nil
}

func (c *SMContext) BuildUpPathChgEventExposureNotification(
	chgEvent *models.UpPathChgEvent,
	srcRoute, tgtRoute *models.RouteToLocation,
) {
	if chgEvent == nil {
		return
	}
	if chgEvent.NotificationUri == "" {
		c.Log.Warnf("No NotificationUri [%s]", chgEvent.NotificationUri)
		return
	}

	en := models.SmfEventExposureEventNotification{
		Event:            models.SmfEvent_UP_PATH_CH,
		SourceTraRouting: srcRoute,
		TargetTraRouting: tgtRoute,
	}
	if srcRoute.Dnai != tgtRoute.Dnai {
		en.SourceDnai = srcRoute.Dnai
		en.TargetDnai = tgtRoute.Dnai
	}
	// TODO: sourceUeIpv4Addr, sourceUeIpv6Prefix, targetUeIpv4Addr, targetUeIpv6Prefix

	k := chgEvent.NotificationUri + chgEvent.NotifCorreId
	if strings.Contains(string(chgEvent.DnaiChgType), "EARLY") {
		en.DnaiChgType = models.DnaiChangeType("EARLY")
		v, ok := c.UpPathChgEarlyNotification[k]
		if ok {
			v.EventNotifs = append(v.EventNotifs, en)
		} else {
			c.UpPathChgEarlyNotification[k] = newEventExposureNotification(
				chgEvent.NotificationUri, chgEvent.NotifCorreId, &en)
		}
	}
	if strings.Contains(string(chgEvent.DnaiChgType), "LATE") {
		en.DnaiChgType = models.DnaiChangeType("LATE")
		v, ok := c.UpPathChgLateNotification[k]
		if ok {
			v.EventNotifs = append(v.EventNotifs, en)
		} else {
			c.UpPathChgLateNotification[k] = newEventExposureNotification(
				chgEvent.NotificationUri, chgEvent.NotifCorreId, &en)
		}
	}
}

func newEventExposureNotification(
	uri, id string,
	en *models.SmfEventExposureEventNotification,
) *EventExposureNotification {
	return &EventExposureNotification{
		NsmfEventExposureNotification: &models.NsmfEventExposureNotification{
			NotifId:     id,
			EventNotifs: []models.SmfEventExposureEventNotification{*en},
		},
		Uri: uri,
	}
}

type NotifCallback func(uri string,
	notification *models.NsmfEventExposureNotification)

func (c *SMContext) SendUpPathChgNotification(chgType string, notifCb NotifCallback) {
	var notifications map[string]*EventExposureNotification
	if chgType == "EARLY" {
		notifications = c.UpPathChgEarlyNotification
	} else if chgType == "LATE" {
		notifications = c.UpPathChgLateNotification
	} else {
		return
	}
	for k, n := range notifications {
		c.Log.Infof("Send UpPathChg Event Exposure Notification [%s][%s] to NEF/AF", chgType, n.NotifId)
		go notifCb(n.Uri, n.NsmfEventExposureNotification)
		delete(notifications, k)
	}
}

func (smContext *SMContext) RemovePDRfromPFCPSession(nodeID pfcpType.NodeID, pdr *PDR) {
	NodeIDtoIP := nodeID.ResolveNodeIdToIp().String()
	pfcpSessCtx := smContext.PFCPContext[NodeIDtoIP]
	delete(pfcpSessCtx.PDRs, pdr.PDRID)
}

// WNC: helper to convert allowed session types to strings for logging
func modelPduSessionTypesToStrings(list []models.PduSessionType) []string {
	if len(list) == 0 {
		return nil
	}
	result := make([]string, len(list))
	for i, t := range list {
		result[i] = string(t)
	}
	return result
}

// WNC: helper to print NAS PDU session types in human readable form
func NasSessionTypeToString(pduType uint8) string {
	switch pduType {
	case nasMessage.PDUSessionTypeIPv4:
		return "IPv4"
	case nasMessage.PDUSessionTypeIPv6:
		return "IPv6"
	case nasMessage.PDUSessionTypeIPv4IPv6:
		return "IPv4v6"
	case nasMessage.PDUSessionTypeEthernet:
		return "Ethernet"
	case nasMessage.PDUSessionTypeUnstructured:
		return "Unstructured"
	default:
		return fmt.Sprintf("0x%02x", pduType)
	}
}

// fallbackPduSessionTypes returns the first PDU session type policy defined in
// the SMF configuration for this DNN/S-NSSAI pair. It is used when the
// subscriber profile does not provide its own policy.
func (smContext *SMContext) fallbackPduSessionTypes() *models.PduSessionTypes {
	if smContext == nil || smContext.SNssai == nil || smContext.Dnn == "" {
		return nil
	}

	self := GetSelf()
	if self == nil || self.UserPlaneInformation == nil {
		return nil
	}

	for _, upNode := range self.UserPlaneInformation.UPFs {
		if upNode == nil || upNode.UPF == nil {
			continue
		}
		for _, snssaiInfo := range upNode.UPF.SNssaiInfos {
			if snssaiInfo == nil || !snssaiInfo.SNssai.EqualModelsSnssai(smContext.SNssai) {
				continue
			}
			for _, dnnInfo := range snssaiInfo.DnnList {
				if dnnInfo != nil && dnnInfo.Dnn == smContext.Dnn && dnnInfo.PduSessionTypes != nil {
					return dnnInfo.PduSessionTypes
				}
			}
		}
	}

	return nil
}

func (smContext *SMContext) IsAllowedPDUSessionType(requestedPDUSessionType uint8) error {
	dnnPDUSessionType := smContext.DnnConfiguration.PduSessionTypes
	policySource := "subscriber"
	if dnnPDUSessionType == nil || len(dnnPDUSessionType.AllowedSessionTypes) == 0 {
		if fallback := smContext.fallbackPduSessionTypes(); fallback != nil {
			dnnPDUSessionType = fallback
			policySource = "smfcfg.yaml"
			if smContext.SNssai != nil {
				logger.CtxLog.Warnf("WNC: Subscriber data missing PDU session types for DNN[%s] S-NSSAI[sst:%d sd:%s]; using smfcfg.yaml values (default:%s allowed:%v)",
					smContext.Dnn, smContext.SNssai.Sst, smContext.SNssai.Sd, fallback.DefaultSessionType, fallback.AllowedSessionTypes)
			} else {
				logger.CtxLog.Warnf("WNC: Subscriber data missing PDU session types for DNN[%s]; using smfcfg.yaml values (default:%s allowed:%v)",
					smContext.Dnn, fallback.DefaultSessionType, fallback.AllowedSessionTypes)
			}
		}
	}
	if dnnPDUSessionType == nil {
		return fmt.Errorf("this SMContext[%s] has no subscription pdu session type info", smContext.Ref)
	}

	// WNC: log which policy source we used (subscriber vs smfcfg fallback)
	logger.CtxLog.Infof("WNC: Using %s session-type policy for DNN[%s]: default=%s allowed=%v",
		policySource, smContext.Dnn, dnnPDUSessionType.DefaultSessionType,
		modelPduSessionTypesToStrings(dnnPDUSessionType.AllowedSessionTypes))

	allowIPv4 := false
	allowIPv6 := false
	allowEthernet := false

	for _, allowedPDUSessionType := range dnnPDUSessionType.AllowedSessionTypes {
		switch allowedPDUSessionType {
		case models.PduSessionType_IPV4:
			allowIPv4 = true
		case models.PduSessionType_IPV6:
			allowIPv6 = true
		case models.PduSessionType_IPV4_V6:
			allowIPv4 = true
			allowIPv6 = true
		case models.PduSessionType_ETHERNET:
			allowEthernet = true
		}
	}

	supportedPDUSessionType := GetSelf().SupportedPDUSessionType
	switch supportedPDUSessionType {
	case "IPv4":
		if !allowIPv4 {
			return fmt.Errorf(
				"No SupportedPDUSessionType[%q] in DNN[%s] configuration",
				supportedPDUSessionType,
				smContext.Dnn,
			)
		}
	case "IPv6":
		if !allowIPv6 {
			return fmt.Errorf(
				"No SupportedPDUSessionType[%q] in DNN[%s] configuration",
				supportedPDUSessionType,
				smContext.Dnn,
			)
		}
	case "IPv4v6":
		if !allowIPv4 && !allowIPv6 {
			return fmt.Errorf(
				"No SupportedPDUSessionType[%q] in DNN[%s] configuration",
				supportedPDUSessionType,
				smContext.Dnn,
			)
		}
	case "Ethernet":
		if !allowEthernet {
			return fmt.Errorf(
				"No SupportedPDUSessionType[%q] in DNN[%s] configuration",
				supportedPDUSessionType,
				smContext.Dnn,
			)
		}
	}

	smContext.EstAcceptCause5gSMValue = 0
	switch nasConvert.PDUSessionTypeToModels(requestedPDUSessionType) {
	case models.PduSessionType_IPV4:
		if allowIPv4 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PduSessionType_IPV4)
		} else {
			return fmt.Errorf("PduSessionType_IPV4 is not allowed in DNN[%s] configuration", smContext.Dnn)
		}
	case models.PduSessionType_IPV6:
		if allowIPv6 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PduSessionType_IPV6)
		} else {
			return fmt.Errorf("PduSessionType_IPV6 is not allowed in DNN[%s] configuration", smContext.Dnn)
		}
	case models.PduSessionType_IPV4_V6:
		if allowIPv4 && allowIPv6 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PduSessionType_IPV4_V6)
		} else if allowIPv4 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PduSessionType_IPV4)
			smContext.EstAcceptCause5gSMValue = nasMessage.Cause5GSMPDUSessionTypeIPv4OnlyAllowed
		} else if allowIPv6 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PduSessionType_IPV6)
			smContext.EstAcceptCause5gSMValue = nasMessage.Cause5GSMPDUSessionTypeIPv6OnlyAllowed
		} else {
			return fmt.Errorf("PduSessionType_IPV4_V6 is not allowed in DNN[%s] configuration", smContext.Dnn)
		}
	case models.PduSessionType_ETHERNET:
		if allowEthernet {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PduSessionType_ETHERNET)
		} else {
			return fmt.Errorf("PduSessionType_ETHERNET is not allowed in DNN[%s] configuration", smContext.Dnn)
		}
	default:
		return fmt.Errorf("Requested PDU Sesstion type[%d] is not supported", requestedPDUSessionType)
	}

	// WNC: trace requested vs selected session type after validation/downgrade
	logger.CtxLog.Infof("WNC: Session type decision for DNN[%s]: requested=%s selected=%s (cause=0x%02x)",
		smContext.Dnn, NasSessionTypeToString(requestedPDUSessionType),
		NasSessionTypeToString(smContext.SelectedPDUSessionType), smContext.EstAcceptCause5gSMValue)
	return nil
}

func (smContext *SMContext) StopT3591() {
	if smContext.T3591 != nil {
		smContext.T3591.Stop()
		smContext.T3591 = nil
	}
}

func (smContext *SMContext) StopT3592() {
	if smContext.T3592 != nil {
		smContext.T3592.Stop()
		smContext.T3592 = nil
	}
}

func (smContextState SMContextState) String() string {
	switch smContextState {
	case InActive:
		return "InActive"
	case ActivePending:
		return "ActivePending"
	case Active:
		return "Active"
	case InActivePending:
		return "InActivePending"
	case ModificationPending:
		return "ModificationPending"
	case PFCPModification:
		return "PFCPModification"
	default:
		return "Unknown State"
	}
}

func (smContext *SMContext) AssignQFI(qosId string) uint8 {
	qfi, ok := smContext.qosDataToQFI[qosId]
	if !ok {
		newId, err := smContext.QFIGenerator.Allocate()
		if err != nil {
			return 0
		}
		smContext.qosDataToQFI[qosId] = uint8(newId)
		return uint8(newId)
	}
	return qfi
}

func (smContext *SMContext) RemoveQFI(qosId string) {
	qfi, ok := smContext.qosDataToQFI[qosId]
	if ok {
		smContext.QFIGenerator.FreeID(int64(qfi))
		delete(smContext.qosDataToQFI, qosId)
		smContext.RemoveQosFlow(qfi)
	}
}

// WNC: Handle PFCP Event Reports for IPv6 Router Solicitation (Phase 3)
// Implements 3GPP TS 23.502 Router Advertisement delivery flow
func (smContext *SMContext) HandleEventReport(eventID uint32) {
	switch eventID {
	case EventIDRouterSolicitation:
		// WNC: Router Solicitation detected from UE - log with URR ID context
		rsMonitorUrrId, exists := smContext.UrrIdMap[RS_MONITOR_URR]
		if exists {
			smContext.Log.Infof("WNC: Router Solicitation event received (URR=%d, Event ID=%d)",
				rsMonitorUrrId, eventID)
		} else {
			smContext.Log.Infof("WNC: Router Solicitation event received (Event ID=%d, no RS_MONITOR_URR)", eventID)
		}

		// Check if this is an IPv6 or dual-stack session
		if smContext.SelectedPDUSessionType != nasMessage.PDUSessionTypeIPv6 &&
			smContext.SelectedPDUSessionType != nasMessage.PDUSessionTypeIPv4IPv6 {
			smContext.Log.Warnf("WNC: Router Solicitation received for non-IPv6 session (PDU Session Type: %d)",
				smContext.SelectedPDUSessionType)
			return
		}

		// Validate IPv6 address and prefix are allocated
		if smContext.PDUAddressIPv6 == nil {
			smContext.Log.Errorln("WNC: Cannot send Router Advertisement - no IPv6 address allocated")
			return
		}

		// Extract the network prefix from the UE's IPv6 address
		ipv6Prefix := GetIPv6PrefixFromAddress(smContext.PDUAddressIPv6, smContext.PDUAddressIPv6PrefixLen)

		if !ValidateIPv6Prefix(ipv6Prefix, smContext.PDUAddressIPv6PrefixLen) {
			smContext.Log.Errorln("WNC: Invalid IPv6 prefix for Router Advertisement")
			return
		}

		// Build Router Advertisement packet
		raPacket := BuildRouterAdvertisement(ipv6Prefix, smContext.PDUAddressIPv6PrefixLen)
		if raPacket == nil {
			smContext.Log.Errorln("WNC: Failed to build Router Advertisement packet")
			return
		}

		smContext.Log.Infof("WNC: Built Router Advertisement for prefix %s/%d (%d bytes)",
			ipv6Prefix, smContext.PDUAddressIPv6PrefixLen, len(raPacket))

		// Trigger Router Advertisement delivery to UPF (Phase 3.1)
		if err := smContext.SendRouterAdvertisement(raPacket); err != nil {
			smContext.Log.Errorf("WNC: Failed to send Router Advertisement: %v", err)
		}

	default:
		smContext.Log.Infof("WNC: Unhandled PFCP event report (Event ID: %d)", eventID)
	}
}

// WNC: SendRouterAdvertisement sends Router Advertisement to UE via UPF (Phase 3.2.4)
// Implemented using HTTP endpoint for Phase 3.1, with PFCP option for Phase 3.2+
func (smContext *SMContext) SendRouterAdvertisement(raPacket []byte) error {
	smContext.Log.Infof("WNC: Sending Router Advertisement (%d bytes) to UPF for UE %s",
		len(raPacket), smContext.Supi)

	// Get delivery method from configuration (default: http)
	deliveryMethod := "http"
	upfHTTPPort := uint16(8080) // Default UPF HTTP port

	if factory.SmfConfig != nil && factory.SmfConfig.Configuration != nil && factory.SmfConfig.Configuration.RouterAdvertisement != nil {
		if factory.SmfConfig.Configuration.RouterAdvertisement.DeliveryMethod != "" {
			deliveryMethod = factory.SmfConfig.Configuration.RouterAdvertisement.DeliveryMethod
		}
		if factory.SmfConfig.Configuration.RouterAdvertisement.UpfHttpPort != 0 {
			upfHTTPPort = factory.SmfConfig.Configuration.RouterAdvertisement.UpfHttpPort
		}
	}

	smContext.Log.Infof("WNC: RA delivery method: %s", deliveryMethod)

	switch deliveryMethod {
	case "http":
		return smContext.sendRouterAdvertisementViaHTTP(raPacket, upfHTTPPort)
	case "pfcp":
		smContext.Log.Warnf("WNC: PFCP RA delivery not yet implemented (Phase 3.2+)")
		return errors.New("WNC: PFCP RA delivery not yet implemented")
	default:
		return fmt.Errorf("WNC: Unknown RA delivery method: %s", deliveryMethod)
	}
}

// WNC: sendRouterAdvertisementViaHTTP sends RA via HTTP endpoint to UPF (Phase 3.2.4)
func (smContext *SMContext) sendRouterAdvertisementViaHTTP(raPacket []byte, upfHTTPPort uint16) error {
	// Get the default data path (first UPF)
	defaultPath := smContext.Tunnel.DataPathPool.GetDefaultPath()
	if defaultPath == nil || defaultPath.FirstDPNode.UpLinkTunnel == nil {
		smContext.Log.Errorln("WNC: No default data path or uplink tunnel found")
		return errors.New("WNC: No UPF available for RA injection")
	}

	// Get UPF from first node in default path
	upfNode := defaultPath.FirstDPNode
	if upfNode.UPF == nil {
		smContext.Log.Errorln("WNC: No UPF in data path node")
		return errors.New("WNC: No UPF in data path node")
	}

	// WNC: Check IPv6 capability before sending RA
	if !upfNode.UPF.SupportsIPv6 {
		smContext.Log.Warnf("WNC: Router Solicitation received but UPF[%s] does not support IPv6, not sending RA",
			upfNode.UPF.Addr)
		return errors.New("WNC: UPF does not support IPv6")
	}

	upfAddr := upfNode.UPF.Addr
	if upfAddr == "" {
		smContext.Log.Errorln("WNC: UPF address is empty")
		return errors.New("WNC: UPF address is empty")
	}

	// Build UPF HTTP endpoint (use net.JoinHostPort to handle IPv6 addresses with brackets)
	upfHTTPEndpoint := "http://" + net.JoinHostPort(upfAddr, strconv.Itoa(int(upfHTTPPort)))

	// Get PFCP Session ID (SEID) - use RemoteSEID (UPF's SEID) for kernel lookup
	pfcpContext := smContext.PFCPContext[upfNode.GetNodeIP()]
	if pfcpContext == nil {
		smContext.Log.Errorln("WNC: PFCP context not found for UPF")
		return errors.New("WNC: PFCP context not found for UPF")
	}
	seid := pfcpContext.RemoteSEID

	// Get downlink PDR ID from session-specific PFCP context
	// Downlink PDRs have SourceInterface = Core (traffic from core network to UE)
	var pdrID uint16
	var foundDownlinkPDR bool
	for id, pdr := range pfcpContext.PDRs {
		if pdr.PDI.SourceInterface.InterfaceValue == pfcpType.SourceInterfaceCore &&
			pdr.FAR != nil && pdr.FAR.ApplyAction.Forw {
			pdrID = id
			foundDownlinkPDR = true
			break
		}
	}

	if !foundDownlinkPDR {
		smContext.Log.Errorln("WNC: No downlink PDR found for this session")
		return errors.New("WNC: No downlink PDR found for this session")
	}

	smContext.Log.Infof("WNC: Sending RA to UPF via HTTP (endpoint=%s, SEID=%d, PDR_ID=%d)",
		upfHTTPEndpoint, seid, pdrID)

	// Call UPF HTTP endpoint
	if err := sendRouterAdvertisementViaHTTPClient(upfHTTPEndpoint, seid, pdrID, raPacket); err != nil {
		smContext.Log.Errorf("WNC: Failed to send RA via HTTP: %v", err)
		return err
	}

	smContext.Log.Infof("WNC: RA successfully sent to UPF via HTTP")
	return nil
}

// WNC: populateRouterSolicitationMonitorFlag reads the routerSolicitationMonitor flag from DNN config
// and persists it in SMContext. This avoids repeated config tree traversal and ensures the flag
// survives UPF pointer churn (handover, release, error recovery, etc.)
func (c *SMContext) populateRouterSolicitationMonitorFlag() {
	// Default to false
	c.EnableRouterSolicitationMonitor = false

	// Try to read from UPF configuration first (most authoritative source)
	if c.SelectedUPF != nil && c.SelectedUPF.UPF != nil {
		for _, snssaiInfo := range c.SelectedUPF.UPF.SNssaiInfos {
			if snssaiInfo == nil || !snssaiInfo.SNssai.EqualModelsSnssai(c.SNssai) {
				continue
			}
			for _, dnnInfo := range snssaiInfo.DnnList {
				if dnnInfo != nil && dnnInfo.Dnn == c.Dnn {
					c.EnableRouterSolicitationMonitor = dnnInfo.RouterSolicitationMonitor
					c.Log.Infof("WNC: Set EnableRouterSolicitationMonitor=%v from UPF config (DNN: %s)",
						c.EnableRouterSolicitationMonitor, c.Dnn)
					return
				}
			}
		}
	}

	// Fallback: try to read from top-level DNN info (if UPF config not available)
	if c.DNNInfo != nil {
		c.EnableRouterSolicitationMonitor = c.DNNInfo.RouterSolicitationMonitor
		c.Log.Infof("WNC: Set EnableRouterSolicitationMonitor=%v from DNNInfo (DNN: %s)",
			c.EnableRouterSolicitationMonitor, c.Dnn)
		return
	}

	c.Log.Debugf("WNC: RouterSolicitationMonitor not found in config, defaulting to false (DNN: %s)", c.Dnn)
}

// WNC: populateDefaultFlowDescriptions reads the defaultUlFlow/defaultDlFlow from DNN config
// and persists them in SMContext. This allows operators to override the catch-all PDR flow descriptions.
// Falls back to hardcoded Open5GS-style wildcards if not configured.
func (c *SMContext) populateDefaultFlowDescriptions() {
	// Hardcoded fallback values (Open5GS-style wildcards)
	const defaultUlFlowFallback = "permit out ip from assigned to any"
	const defaultDlFlowFallback = "permit out ip from any to assigned"

	// Initialize with fallback values
	c.DefaultUlFlow = defaultUlFlowFallback
	c.DefaultDlFlow = defaultDlFlowFallback

	// Try to read from UPF configuration first (most authoritative source)
	if c.SelectedUPF != nil && c.SelectedUPF.UPF != nil {
		for _, snssaiInfo := range c.SelectedUPF.UPF.SNssaiInfos {
			if snssaiInfo == nil || !snssaiInfo.SNssai.EqualModelsSnssai(c.SNssai) {
				continue
			}
			for _, dnnInfo := range snssaiInfo.DnnList {
				if dnnInfo != nil && dnnInfo.Dnn == c.Dnn {
					if dnnInfo.DefaultUlFlow != "" {
						c.DefaultUlFlow = dnnInfo.DefaultUlFlow
					}
					if dnnInfo.DefaultDlFlow != "" {
						c.DefaultDlFlow = dnnInfo.DefaultDlFlow
					}
					c.Log.Infof("WNC: Set default flows from UPF config (DNN: %s) - UL: %s, DL: %s",
						c.Dnn, c.DefaultUlFlow, c.DefaultDlFlow)
					return
				}
			}
		}
	}

	// Fallback: try to read from top-level DNN info (if UPF config not available)
	if c.DNNInfo != nil {
		if c.DNNInfo.DefaultUlFlow != "" {
			c.DefaultUlFlow = c.DNNInfo.DefaultUlFlow
		}
		if c.DNNInfo.DefaultDlFlow != "" {
			c.DefaultDlFlow = c.DNNInfo.DefaultDlFlow
		}
		c.Log.Infof("WNC: Set default flows from DNNInfo (DNN: %s) - UL: %s, DL: %s",
			c.Dnn, c.DefaultUlFlow, c.DefaultDlFlow)
		return
	}

	c.Log.Debugf("WNC: Default flows not found in config, using fallback (DNN: %s) - UL: %s, DL: %s",
		c.Dnn, c.DefaultUlFlow, c.DefaultDlFlow)
}
