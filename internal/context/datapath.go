package context

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/smf/internal/logger"
	"github.com/free5gc/smf/internal/util"
	"github.com/free5gc/smf/pkg/factory"
)

// Refer to TS 23.501 5.7.4
var standardGbr5QIs = map[int32]struct{}{
	1:  {},
	2:  {},
	3:  {},
	4:  {},
	65: {},
	66: {},
	67: {},
	75: {},
	71: {},
	72: {},
	73: {},
	74: {},
	76: {},
}

// GTPTunnel represents the GTP tunnel information
type GTPTunnel struct {
	SrcEndPoint  *DataPathNode
	DestEndPoint *DataPathNode

	TEID uint32
	PDR  *PDR
}

type DataPathNode struct {
	UPF *UPF
	// DataPathToAN *DataPathDownLink
	// DataPathToDN map[string]*DataPathUpLink //uuid to DataPathLink

	UpLinkTunnel   *GTPTunnel
	DownLinkTunnel *GTPTunnel

	// WNC: RS-monitor PDR for Router Solicitation event-based reporting
	// This PDR has higher precedence than general UL PDR and narrow SDF filter
	// for ICMPv6 RS packets (permit out 58 from fe80::/64 to ff02::2)
	RSMonitorPDR *PDR

	// for UE Routing Topology
	// for special case:
	// branching & leafnode

	// InUse                bool
	IsBranchingPoint bool
	// DLDataPathLinkForPSA *DataPathUpLink
	// BPUpLinkPDRs         map[string]*DataPathDownLink // uuid to UpLink
}

type DataPath struct {
	PathID int64
	// meta data
	Activated         bool
	IsDefaultPath     bool
	GBRFlow           bool
	Destination       Destination
	HasBranchingPoint bool
	// WNC: Session type for IPv4/IPv6/dual-stack handling (Phase 2)
	PDUSessionType uint8
	// Data Path Double Link List
	FirstDPNode *DataPathNode
}

type DataPathPool map[int64]*DataPath

type Destination struct {
	DestinationIP   string
	DestinationPort string
	Url             string
}

func NewDataPathNode() *DataPathNode {
	node := &DataPathNode{
		UpLinkTunnel:   &GTPTunnel{},
		DownLinkTunnel: &GTPTunnel{},
	}
	return node
}

func NewDataPath() *DataPath {
	dataPath := &DataPath{
		Destination: Destination{
			DestinationIP:   "",
			DestinationPort: "",
			Url:             "",
		},
	}

	return dataPath
}

func NewDataPathPool() DataPathPool {
	pool := make(map[int64]*DataPath)
	return pool
}

func (node *DataPathNode) AddNext(next *DataPathNode) {
	node.DownLinkTunnel.SrcEndPoint = next
}

func (node *DataPathNode) AddPrev(prev *DataPathNode) {
	node.UpLinkTunnel.SrcEndPoint = prev
}

func (node *DataPathNode) Next() *DataPathNode {
	if node.DownLinkTunnel == nil {
		return nil
	}
	next := node.DownLinkTunnel.SrcEndPoint
	return next
}

func (node *DataPathNode) Prev() *DataPathNode {
	if node.UpLinkTunnel == nil {
		return nil
	}
	prev := node.UpLinkTunnel.SrcEndPoint
	return prev
}

func (node *DataPathNode) ActivateUpLinkTunnel(smContext *SMContext) error {
	logger.CtxLog.Traceln("In ActivateUpLinkTunnel")

	var err error
	node.UpLinkTunnel.SrcEndPoint = node.Prev()
	node.UpLinkTunnel.DestEndPoint = node

	destUPF := node.UPF
	if node.UpLinkTunnel.PDR, err = destUPF.AddPDR(); err != nil {
		logger.CtxLog.Errorln("In ActivateUpLinkTunnel UPF IP: ", node.UPF.NodeID.ResolveNodeIdToIp().String())
		logger.CtxLog.Errorln("Allocate PDR Error: ", err)
		return fmt.Errorf("Add PDR failed: %s", err)
	}

	if err = smContext.PutPDRtoPFCPSession(destUPF.NodeID, node.UpLinkTunnel.PDR); err != nil {
		logger.CtxLog.Errorln("Put PDR Error: ", err)
		return err
	}

	node.UpLinkTunnel.TEID = smContext.LocalULTeid

	return nil
}

func (node *DataPathNode) ActivateDownLinkTunnel(smContext *SMContext) error {
	logger.CtxLog.Traceln("In ActivateDownLinkTunnel")

	var err error
	node.DownLinkTunnel.SrcEndPoint = node.Next()
	node.DownLinkTunnel.DestEndPoint = node

	destUPF := node.UPF
	if node.DownLinkTunnel.PDR, err = destUPF.AddPDR(); err != nil {
		logger.CtxLog.Errorln("In ActivateDownLinkTunnel UPF IP: ", node.UPF.NodeID.ResolveNodeIdToIp().String())
		logger.CtxLog.Errorln("Allocate PDR Error: ", err)
		return fmt.Errorf("Add PDR failed: %s", err)
	}

	if err = smContext.PutPDRtoPFCPSession(destUPF.NodeID, node.DownLinkTunnel.PDR); err != nil {
		logger.CtxLog.Errorln("Put PDR Error: ", err)
		return err
	}

	node.DownLinkTunnel.TEID = smContext.LocalDLTeid

	return nil
}

func (node *DataPathNode) DeactivateUpLinkTunnel(smContext *SMContext) {
	if pdr := node.UpLinkTunnel.PDR; pdr != nil {
		smContext.RemovePDRfromPFCPSession(node.UPF.NodeID, pdr)
		err := node.UPF.RemovePDR(pdr)
		if err != nil {
			logger.CtxLog.Warnln("Deactivated UpLinkTunnel", err)
		}

		if far := pdr.FAR; far != nil {
			err = node.UPF.RemoveFAR(far)
			if err != nil {
				logger.CtxLog.Warnln("Deactivated UpLinkTunnel", err)
			}

			bar := far.BAR
			if bar != nil {
				err = node.UPF.RemoveBAR(bar)
				if err != nil {
					logger.CtxLog.Warnln("Deactivated UpLinkTunnel", err)
				}
			}
		}
		if qerList := pdr.QER; qerList != nil {
			for _, qer := range qerList {
				if qer != nil {
					err = node.UPF.RemoveQER(qer)
					if err != nil {
						logger.CtxLog.Warnln("Deactivated UpLinkTunnel", err)
					}
				}
			}
		}
	}
}

func (node *DataPathNode) DeactivateDownLinkTunnel(smContext *SMContext) {
	if pdr := node.DownLinkTunnel.PDR; pdr != nil {
		smContext.RemovePDRfromPFCPSession(node.UPF.NodeID, pdr)
		err := node.UPF.RemovePDR(pdr)
		if err != nil {
			logger.CtxLog.Warnln("Deactivated DownLinkTunnel", err)
		}

		if far := pdr.FAR; far != nil {
			err = node.UPF.RemoveFAR(far)
			if err != nil {
				logger.CtxLog.Warnln("Deactivated DownLinkTunnel", err)
			}

			bar := far.BAR
			if bar != nil {
				err = node.UPF.RemoveBAR(bar)
				if err != nil {
					logger.CtxLog.Warnln("Deactivated DownLinkTunnel", err)
				}
			}
		}
		if qerList := pdr.QER; qerList != nil {
			for _, qer := range qerList {
				if qer != nil {
					err = node.UPF.RemoveQER(qer)
					if err != nil {
						logger.CtxLog.Warnln("Deactivated UpLinkTunnel", err)
					}
				}
			}
		}
	}
}

// WNC: Deactivate RS-monitor PDR for Router Solicitation event-based reporting
func (node *DataPathNode) DeactivateRSMonitorPDR(smContext *SMContext) {
	if pdr := node.RSMonitorPDR; pdr != nil {
		logger.CtxLog.Infof("WNC: Deactivating RS-monitor PDR %d for UPF %s",
			pdr.PDRID, node.UPF.NodeID.ResolveNodeIdToIp().String())

		// First, mark URRs for PFCP removal and clean up UPF urrPool
		if urrList := pdr.URR; urrList != nil && len(urrList) > 0 {
			for _, urr := range urrList {
				if urr != nil {
					// Set URR state to RULE_REMOVE so PFCP builder will send RemoveURR
					urr.State = RULE_REMOVE
					logger.CtxLog.Infof("WNC: Marked RS-monitor URR %d for PFCP removal (state=RULE_REMOVE)", urr.URRID)

					// Remove from UPF's urrPool (but NOT from urrIDGenerator since it wasn't allocated there)
					// The URR ID was allocated via smContext.UrrIDGenerator, not node.UPF.urrIDGenerator
					if err := node.UPF.IsAssociated(); err == nil {
						node.UPF.urrPool.Delete(urr.URRID)
						logger.CtxLog.Infof("WNC: Removed RS-monitor URR %d from UPF urrPool", urr.URRID)
					}

					// Remove from SMF's UrrUpfMap
					currentUUID := node.UPF.UUID()
					urrKey := getUrrIdKey(currentUUID, urr.URRID)
					delete(smContext.UrrUpfMap, urrKey)
					logger.CtxLog.Infof("WNC: Removed RS-monitor URR %d from UrrUpfMap (key: %s)", urr.URRID, urrKey)
				}
			}
		}

		// Mark PDR for PFCP removal
		pdr.State = RULE_REMOVE
		logger.CtxLog.Infof("WNC: Marked RS-monitor PDR %d for PFCP removal (state=RULE_REMOVE)", pdr.PDRID)

		// Remove PDR from PFCP session context and UPF pdrPool
		smContext.RemovePDRfromPFCPSession(node.UPF.NodeID, pdr)
		err := node.UPF.RemovePDR(pdr)
		if err != nil {
			logger.CtxLog.Warnf("WNC: Failed to remove RS-monitor PDR from UPF: %v", err)
		}

		// NOTE: Do NOT remove FAR - RS PDR reuses the UL PDR's FAR which will be
		// removed when DeactivateUpLinkTunnel is called

		// NOTE: Do NOT free the global URR ID here - this function runs per-node,
		// but the RS_MONITOR_URR ID is shared across all nodes in the session.
		// The ID will be freed once during session teardown in DeactivateTunnelAndPDR.

		// Nil out the pointer to prevent reuse
		node.RSMonitorPDR = nil
		logger.CtxLog.Infof("WNC: RS-monitor PDR node-local cleanup complete")
	}
}

func (node *DataPathNode) GetUPFID() (id string, err error) {
	node_ip := node.GetNodeIP()
	var exist bool

	if id, exist = smfContext.UserPlaneInformation.UPFsIPtoID[node_ip]; !exist {
		err = fmt.Errorf("UPNode IP %s doesn't exist in smfcfg.yaml", node_ip)
		return "", err
	}

	return id, nil
}

func (node *DataPathNode) GetNodeIP() (ip string) {
	ip = node.UPF.NodeID.ResolveNodeIdToIp().String()
	return
}

func (node *DataPathNode) IsANUPF() bool {
	if node.Prev() == nil {
		return true
	} else {
		return false
	}
}

func (node *DataPathNode) IsAnchorUPF() bool {
	if node.Next() == nil {
		return true
	} else {
		return false
	}
}

func (node *DataPathNode) GetUpLinkPDR() (pdr *PDR) {
	return node.UpLinkTunnel.PDR
}

func (node *DataPathNode) GetUpLinkFAR() (far *FAR) {
	return node.UpLinkTunnel.PDR.FAR
}

func (dataPathPool DataPathPool) GetDefaultPath() *DataPath {
	for _, path := range dataPathPool {
		if path.IsDefaultPath {
			return path
		}
	}
	return nil
}

func (dataPathPool DataPathPool) ResetDefaultPath() error {
	for _, path := range dataPathPool {
		path.IsDefaultPath = false
	}

	return nil
}

func (dataPath *DataPath) String() string {
	firstDPNode := dataPath.FirstDPNode

	var str string

	str += "DataPath Meta Information\n"
	str += "Activated: " + strconv.FormatBool(dataPath.Activated) + "\n"
	str += "IsDefault Path: " + strconv.FormatBool(dataPath.IsDefaultPath) + "\n"
	str += "Has Braching Point: " + strconv.FormatBool(dataPath.HasBranchingPoint) + "\n"
	str += "Destination IP: " + dataPath.Destination.DestinationIP + "\n"
	str += "Destination Port: " + dataPath.Destination.DestinationPort + "\n"

	str += "DataPath Routing Information\n"
	index := 1
	for curDPNode := firstDPNode; curDPNode != nil; curDPNode = curDPNode.Next() {
		str += strconv.Itoa(index) + "th Node in the Path\n"
		str += "Current UPF IP: " + curDPNode.GetNodeIP() + "\n"
		str += "Current UPF ID: " + curDPNode.UPF.GetUPFID() + "\n"
		if curDPNode.Prev() != nil {
			str += "Previous UPF IP: " + curDPNode.Prev().GetNodeIP() + "\n"
			str += "Previous UPF ID: " + curDPNode.Prev().UPF.GetUPFID() + "\n"
		} else {
			str += "Previous UPF IP: None\n"
		}

		if curDPNode.Next() != nil {
			str += "Next UPF IP: " + curDPNode.Next().GetNodeIP() + "\n"
			str += "Next UPF ID: " + curDPNode.Next().UPF.GetUPFID() + "\n"
		} else {
			str += "Next UPF IP: None\n"
		}

		index++
	}

	return str
}

func getUrrIdKey(uuid string, urrId uint32) string {
	return uuid + ":" + strconv.Itoa(int(urrId))
}

func GetUpfIdFromUrrIdKey(urrIdKey string) string {
	return strings.Split(urrIdKey, ":")[0]
}

func (node DataPathNode) addUrrToNode(smContext *SMContext, urrId uint32, isMeasurePkt, isMeasureBeforeQos bool) {
	var urr *URR
	var ok bool
	var err error
	currentUUID := node.UPF.UUID()
	id := getUrrIdKey(currentUUID, urrId)

	if urr, ok = smContext.UrrUpfMap[id]; !ok {
		if urr, err = node.UPF.AddURR(urrId,
			NewMeasureInformation(isMeasurePkt, isMeasureBeforeQos),
			NewMeasurementPeriod(smContext.UrrReportTime),
			NewVolumeThreshold(smContext.UrrReportThreshold)); err != nil {
			logger.PduSessLog.Errorln("new URR failed")
			return
		}
	}

	if urr != nil {
		if node.UpLinkTunnel != nil && node.UpLinkTunnel.PDR != nil {
			node.UpLinkTunnel.PDR.AppendURRs([]*URR{urr})
		}
		if node.DownLinkTunnel != nil && node.DownLinkTunnel.PDR != nil {
			node.DownLinkTunnel.PDR.AppendURRs([]*URR{urr})
		}
	}
}

// Add reserve urr to datapath UPF
func (datapath *DataPath) addUrrToPath(smContext *SMContext) {
	if smContext.UrrReportTime == 0 && smContext.UrrReportThreshold == 0 {
		logger.PduSessLog.Errorln("URR Report time and threshold is 0")
		return
	}

	for curDataPathNode := datapath.FirstDPNode; curDataPathNode != nil; curDataPathNode = curDataPathNode.Next() {
		var MBQEUrrId uint32
		var MAQEUrrId uint32

		if curDataPathNode.IsANUPF() {
			if curDataPathNode.Next() == nil {
				MBQEUrrId = smContext.UrrIdMap[N3N6_MBQE_URR]
				MAQEUrrId = smContext.UrrIdMap[N3N6_MAQE_URR]
			} else {
				MBQEUrrId = smContext.UrrIdMap[N3N9_MBQE_URR]
				MAQEUrrId = smContext.UrrIdMap[N3N9_MAQE_URR]
			}
		} else {
			MBQEUrrId = smContext.UrrIdMap[N9N6_MBQE_URR]
			MAQEUrrId = smContext.UrrIdMap[N9N6_MAQE_URR]
		}

		curDataPathNode.addUrrToNode(smContext, MBQEUrrId, true, true)
		curDataPathNode.addUrrToNode(smContext, MAQEUrrId, true, false)
	}
}

// WNC: Add Router Solicitation monitoring URR to datapath (independent of CHF charging)
// This function creates a URR specifically for RS event reporting when routerSolicitationMonitor is enabled
func (datapath *DataPath) addRSMonitorUrrToPath(smContext *SMContext) {
	// Check if session has IPv6 support
	hasIPv6 := smContext.SelectedPDUSessionType == nasMessage.PDUSessionTypeIPv6 ||
		smContext.SelectedPDUSessionType == nasMessage.PDUSessionTypeIPv4IPv6

	if !hasIPv6 {
		logger.PduSessLog.Debugf("WNC: Skipping RS monitor URR creation - session is not IPv6")
		return
	}

	// WNC: Use persisted flag from SMContext instead of traversing config tree
	// This avoids repeated lookups and works even when SelectedUPF is nil
	if !smContext.EnableRouterSolicitationMonitor {
		logger.PduSessLog.Debugf("WNC: Skipping RS monitor URR creation - RouterSolicitationMonitor disabled for DNN %s",
			smContext.Dnn)
		return
	}

	// Allocate URR ID for RS monitoring
	if _, exists := smContext.UrrIdMap[RS_MONITOR_URR]; !exists {
		if id, err := smContext.UrrIDGenerator.Allocate(); err == nil {
			smContext.UrrIdMap[RS_MONITOR_URR] = uint32(id)
			logger.PduSessLog.Infof("WNC: Allocated URR ID %d for Router Solicitation monitoring (DNN: %s)",
				id, smContext.Dnn)
		} else {
			logger.PduSessLog.Errorf("WNC: Failed to allocate URR ID for RS monitoring: %v", err)
			return
		}
	}

	rsMonitorUrrId := smContext.UrrIdMap[RS_MONITOR_URR]

	// Add RS monitoring URR to uplink PDR only (to detect RS from UE)
	for curDataPathNode := datapath.FirstDPNode; curDataPathNode != nil; curDataPathNode = curDataPathNode.Next() {
		// Only add to anchor UPF (PSA)
		if curDataPathNode.IsAnchorUPF() {
			var urr *URR
			var ok bool
			var err error
			currentUUID := curDataPathNode.UPF.UUID()
			id := getUrrIdKey(currentUUID, rsMonitorUrrId)

			if urr, ok = smContext.UrrUpfMap[id]; !ok {
				// WNC: Create URR with minimal configuration for RS event reporting only
				// Only set MeasureMethod and ReportingTriggers.Start
				// Do NOT set MeasurementPeriod or VolumeThreshold to avoid TS 29.244 violations
				// (setting trigger bits without corresponding IEs)
				if urr, err = curDataPathNode.UPF.AddURR(rsMonitorUrrId,
					NewMeasureInformation(true, false)); err != nil { // Measure volume, after QoS
					logger.PduSessLog.Errorf("WNC: Failed to create RS monitor URR: %v", err)
					return
				}

				// WNC: Do NOT set ReportingTriggers.Start to avoid START reports on arbitrary packets
				// Only rely on ReportingTriggers.Eveth (event-based) which will be set in urrToCreateURR
				// when building PFCP message. This ensures reports are only sent for actual RS packets.
				// urr.ReportingTrigger.Start = true  // REMOVED - causes false reports

				smContext.UrrUpfMap[id] = urr
				logger.PduSessLog.Infof("WNC: Created RS monitor URR %d for UPF %s (DNN: %s, triggers: Start=false, Eveth will be added in PFCP builder)",
					rsMonitorUrrId, currentUUID, smContext.Dnn)
			}

			// WNC: DO NOT attach URR to general uplink PDR here!
			// The RS-monitor URR should ONLY be attached to the dedicated RS-specific PDR
			// created in ActivateTunnelAndPDR() with the narrow ICMPv6 SDF filter.
			// Attaching it here would cause every packet (including DNS) to trigger URR logic.
			//
			// OLD CODE (REMOVED):
			// if curDataPathNode.UpLinkTunnel != nil && curDataPathNode.UpLinkTunnel.PDR != nil {
			//     curDataPathNode.UpLinkTunnel.PDR.AppendURRs([]*URR{urr})
			// }
			//
			// The URR will be attached to the RS-monitor PDR at line ~802 in ActivateTunnelAndPDR()
			logger.PduSessLog.Infof("WNC: RS monitor URR %d created but NOT attached to general UL PDR (will attach to RS-specific PDR only)",
				rsMonitorUrrId)
		}
	}
}

// WNC: buildSessionAmbrMBR converts a session rule's AuthSessAmbr into a PFCP MBR.
// Returns (nil, nil) when no session AMBR is present, so the caller skips the
// session-AMBR QER instead of dereferencing a nil pointer and panicking (observed
// when the SM subscription data carried no sessionAmbr for the DNN).
func buildSessionAmbrMBR(ambr *models.Ambr) (*pfcpType.MBR, error) {
	if ambr == nil {
		return nil, nil
	}
	ulMBR, err := util.BitRateTokbps(ambr.Uplink)
	if err != nil {
		return nil, err
	}
	dlMBR, err := util.BitRateTokbps(ambr.Downlink)
	if err != nil {
		return nil, err
	}
	return &pfcpType.MBR{ULMBR: ulMBR, DLMBR: dlMBR}, nil
}

func (dataPath *DataPath) ActivateTunnelAndPDR(smContext *SMContext, precedence uint32) {
	smContext.AllocateLocalSEIDForDataPath(dataPath)

	firstDPNode := dataPath.FirstDPNode
	logger.PduSessLog.Traceln("In ActivateTunnelAndPDR")
	logger.PduSessLog.Traceln(dataPath.String())
	// Activate Tunnels
	for node := firstDPNode; node != nil; node = node.Next() {
		logger.PduSessLog.Traceln("Current DP Node IP: ", node.UPF.NodeID.ResolveNodeIdToIp().String())
		if err := node.ActivateUpLinkTunnel(smContext); err != nil {
			logger.CtxLog.Warnln(err)
			return
		}
		if err := node.ActivateDownLinkTunnel(smContext); err != nil {
			logger.CtxLog.Warnln(err)
			return
		}
	}

	// Note: This should be after Activate Tunnels
	if smContext.UrrReportTime != 0 || smContext.UrrReportThreshold != 0 {
		dataPath.addUrrToPath(smContext)
		logger.PduSessLog.Tracef("Create URR: UrrReportTime [%v],  UrrReportThreshold: [%v]",
			smContext.UrrReportTime, smContext.UrrReportThreshold)
	} else {
		logger.PduSessLog.Warn("No Create URR")
	}

	// WNC: Create URR for Router Solicitation monitoring (independent of CHF charging)
	// This ensures RS event reporting works even when CHF is disabled
	dataPath.addRSMonitorUrrToPath(smContext)

	sessionRule := smContext.SelectedSessionRule()

	// Activate PDR
	for curDataPathNode := firstDPNode; curDataPathNode != nil; curDataPathNode = curDataPathNode.Next() {
		var defaultQER *QER
		var ambrQER *QER
		currentUUID := curDataPathNode.UPF.uuid

		// WNC: Guard against a missing session AMBR. SelectedSessionRule() can return a
		// rule whose AuthSessAmbr is nil (e.g. the PCF echoed a nil SubsSessAmbr because
		// the SM subscription data had no sessionAmbr for the DNN). Skip the session-AMBR
		// QER in that case instead of dereferencing a nil pointer and panicking; the PDU
		// session still comes up, just without an enforced session AMBR.
		var sessionAmbr *models.Ambr
		if sessionRule != nil {
			sessionAmbr = sessionRule.AuthSessAmbr
		}
		ambrMBR, ambrErr := buildSessionAmbrMBR(sessionAmbr)
		if ambrErr != nil {
			logger.PduSessLog.Errorln("Cannot get the unit of session AMBR (ULMBR/DLMBR), please check the settings in web console")
			return
		}
		if ambrMBR == nil {
			logger.PduSessLog.Warnf("[WNC] No session AMBR for DNN[%s]; skipping session-AMBR QER", smContext.Dnn)
		} else if qerId, okCurrentId := smContext.AMBRQerMap[currentUUID]; !okCurrentId {
			if newQER, err := curDataPathNode.UPF.AddQER(); err != nil {
				logger.PduSessLog.Errorln("new QER failed")
				return
			} else {
				newQER.QFI.QFI = sessionRule.DefQosQFI
				newQER.GateStatus = &pfcpType.GateStatus{
					ULGate: pfcpType.GateOpen,
					DLGate: pfcpType.GateOpen,
				}
				newQER.MBR = ambrMBR
				ambrQER = newQER
			}
			smContext.AMBRQerMap[currentUUID] = ambrQER.QERID
		} else if oldQER, okQerId := curDataPathNode.UPF.qerPool.Load(qerId); okQerId {
			ambrQER = oldQER.(*QER)
		}

		if dataPath.IsDefaultPath {
			id := getQosIdKey(currentUUID, sessionRule.DefQosQFI)
			if qerId, okId := smContext.QerUpfMap[id]; !okId {
				if newQER, err := curDataPathNode.UPF.AddQER(); err != nil {
					logger.PduSessLog.Errorln("new QER failed")
					return
				} else {
					newQER.QFI.QFI = sessionRule.DefQosQFI
					newQER.GateStatus = &pfcpType.GateStatus{
						ULGate: pfcpType.GateOpen,
						DLGate: pfcpType.GateOpen,
					}
					defaultQER = newQER
				}
				smContext.QerUpfMap[id] = defaultQER.QERID
			} else if oldQER, okQerId := curDataPathNode.UPF.qerPool.Load(qerId); okQerId {
				defaultQER = oldQER.(*QER)
			}
		}

		logger.CtxLog.Traceln("Calculate ", curDataPathNode.UPF.PFCPAddr().String())
		curULTunnel := curDataPathNode.UpLinkTunnel
		curDLTunnel := curDataPathNode.DownLinkTunnel

		// Setup UpLink PDR
		if curULTunnel != nil {
			ULPDR := curULTunnel.PDR
			ULDestUPF := curULTunnel.DestEndPoint.UPF
			if defaultQER != nil {
				ULPDR.QER = append(ULPDR.QER, defaultQER)
			}
			if ambrQER != nil && !dataPath.GBRFlow {
				ULPDR.QER = append(ULPDR.QER, ambrQER)
			}

			ULPDR.Precedence = precedence

			var iface *UPFInterfaceInfo
			if curDataPathNode.IsANUPF() {
				iface = ULDestUPF.GetInterface(models.UpInterfaceType_N3, smContext.Dnn)
			} else {
				iface = ULDestUPF.GetInterface(models.UpInterfaceType_N9, smContext.Dnn)
			}

			if iface == nil {
				logger.CtxLog.Errorln("Can not get interface")
				return
			}

			if upIP, err := iface.IP(smContext.SelectedPDUSessionType); err != nil {
				logger.CtxLog.Errorln("ActivateTunnelAndPDR failed", err)
				return
			} else {
				// WNC: Build F-TEID with correct IP version based on actual interface IP
				var fteid *pfcpType.FTEID
				var isIPv6Tunnel bool
				if upIPv4 := upIP.To4(); upIPv4 != nil {
					// IPv4 F-TEID
					fteid = &pfcpType.FTEID{
						V4:          true,
						V6:          false,
						Ipv4Address: upIPv4,
						Teid:        curULTunnel.TEID,
					}
					isIPv6Tunnel = false
					logger.CtxLog.Debugf("WNC: Set ULPDR F-TEID with IPv4 %s TEID 0x%x", upIPv4, curULTunnel.TEID)
				} else if upIPv6 := upIP.To16(); upIPv6 != nil {
					// IPv6 F-TEID
					fteid = &pfcpType.FTEID{
						V4:          false,
						V6:          true,
						Ipv6Address: upIPv6,
						Teid:        curULTunnel.TEID,
					}
					isIPv6Tunnel = true
					logger.CtxLog.Debugf("WNC: Set ULPDR F-TEID with IPv6 %s TEID 0x%x", upIPv6, curULTunnel.TEID)
				} else {
					logger.CtxLog.Errorf("WNC: Invalid IP address from interface: %v", upIP)
					return
				}

				ULPDR.PDI = PDI{
					SourceInterface: pfcpType.SourceInterface{InterfaceValue: pfcpType.SourceInterfaceAccess},
					LocalFTeid:      fteid,
					NetworkInstance: &pfcpType.NetworkInstance{
						NetworkInstance: smContext.Dnn,
						FQDNEncoding:    factory.SmfConfig.Configuration.NwInstFqdnEncoding,
					},
				}
				// WNC: Set UE IP Address for IP sessions (supports IPv4, IPv6, dual-stack)
				ipv4, hasIPv4 := smContext.PDUIPv4()
				ipv6, hasIPv6 := smContext.PDUIPv6()
				ipv6LinkLocal, hasIPv6LinkLocal := smContext.PDUIPv6LinkLocal()

				if hasIPv4 || hasIPv6 || hasIPv6LinkLocal {
					ULPDR.PDI.UEIPAddress = &pfcpType.UEIPAddress{
						V4: hasIPv4,
						V6: hasIPv6 || hasIPv6LinkLocal, // Accept both global and link-local IPv6
					}
					if hasIPv4 {
						ULPDR.PDI.UEIPAddress.Ipv4Address = ipv4
					}
					if hasIPv6 {
						ULPDR.PDI.UEIPAddress.Ipv6Address = ipv6
						// Only signal IPv6 prefix delegation when we actually have a prefix length
						if smContext.PDUAddressIPv6PrefixLen > 0 {
							ULPDR.PDI.UEIPAddress.Ipv6d = true // IPv6 Prefix Delegation flag
							ULPDR.PDI.UEIPAddress.Ipv6PrefixDelegationBits = smContext.PDUAddressIPv6PrefixLen
						}
					}
					// WNC: Store link-local address for kernel matching (RS/RA/NS/NA/DAD support)
					// The kernel will check both global and link-local addresses
					if hasIPv6LinkLocal {
						// Note: We'll pass link-local via a custom field or separate PDR
						// For now, log it for visibility
						logger.CtxLog.Infof("WNC: UE has link-local IPv6 %s for RS/RA/NS/NA/DAD support", ipv6LinkLocal)
					}
					if hasIPv4 && hasIPv6 {
						logger.CtxLog.Infof("WNC: Set ULPDR UEIPAddress with dual-stack IPv4 %s and IPv6 %s/%d (link-local: %s)",
							ipv4, ipv6, smContext.PDUAddressIPv6PrefixLen, ipv6LinkLocal)
					} else if hasIPv6 {
						logger.CtxLog.Infof("WNC: Set ULPDR UEIPAddress with IPv6 %s/%d (link-local: %s)",
							ipv6, smContext.PDUAddressIPv6PrefixLen, ipv6LinkLocal)
					} else {
						logger.CtxLog.Infof("WNC: Set ULPDR UEIPAddress with IPv4 %s", ipv4)
					}
				} else if !smContext.IsIPSession() {
					logger.CtxLog.Infof("WNC: Skipping UE IP address in ULPDR PDI for non-IP session type 0x%02x",
						smContext.SelectedPDUSessionType)
				}

				// WNC: Match outer header removal to F-TEID IP family (3GPP TS 29.244 compliance)
				if isIPv6Tunnel {
					ULPDR.OuterHeaderRemoval = &pfcpType.OuterHeaderRemoval{
						OuterHeaderRemovalDescription: pfcpType.OuterHeaderRemovalGtpUUdpIpv6,
					}
					logger.CtxLog.Debugf("WNC: Set ULPDR OuterHeaderRemoval to GTP-U/UDP/IPv6")
				} else {
					ULPDR.OuterHeaderRemoval = &pfcpType.OuterHeaderRemoval{
						OuterHeaderRemovalDescription: pfcpType.OuterHeaderRemovalGtpUUdpIpv4,
					}
					logger.CtxLog.Debugf("WNC: Set ULPDR OuterHeaderRemoval to GTP-U/UDP/IPv4")
				}
			}

			ULFAR := ULPDR.FAR
			// If the flow is disable, the tunnel and the session rules will not be created

			ULFAR.ApplyAction = pfcpType.ApplyAction{
				Buff: false,
				Drop: false,
				Dupl: false,
				Forw: true,
				Nocp: false,
			}

			ULFAR.ForwardingParameters = &ForwardingParameters{
				DestinationInterface: pfcpType.DestinationInterface{
					InterfaceValue: pfcpType.DestinationInterfaceCore,
				},
				NetworkInstance: &pfcpType.NetworkInstance{
					NetworkInstance: smContext.Dnn,
					FQDNEncoding:    factory.SmfConfig.Configuration.NwInstFqdnEncoding,
				},
			}

			if nextULDest := curDataPathNode.Next(); nextULDest != nil {
				nextULTunnel := nextULDest.UpLinkTunnel
				iface = nextULTunnel.DestEndPoint.UPF.GetInterface(models.UpInterfaceType_N9, smContext.Dnn)

				if upIP, err := iface.IP(smContext.SelectedPDUSessionType); err != nil {
					logger.CtxLog.Errorln("ActivateTunnelAndPDR failed", err)
					return
				} else {
					// WNC: Build Outer Header Creation with correct IP version for UL N9
					if upIPv4 := upIP.To4(); upIPv4 != nil {
						ULFAR.ForwardingParameters.OuterHeaderCreation = &pfcpType.OuterHeaderCreation{
							OuterHeaderCreationDescription: pfcpType.OuterHeaderCreationGtpUUdpIpv4,
							Ipv4Address:                    upIPv4,
							Teid:                           nextULTunnel.TEID,
						}
						logger.CtxLog.Debugf("WNC: Set ULFAR N9 OuterHeader with IPv4 %s TEID 0x%x", upIPv4, nextULTunnel.TEID)
					} else if upIPv6 := upIP.To16(); upIPv6 != nil {
						ULFAR.ForwardingParameters.OuterHeaderCreation = &pfcpType.OuterHeaderCreation{
							OuterHeaderCreationDescription: pfcpType.OuterHeaderCreationGtpUUdpIpv6,
							Ipv6Address:                    upIPv6,
							Teid:                           nextULTunnel.TEID,
						}
						logger.CtxLog.Debugf("WNC: Set ULFAR N9 OuterHeader with IPv6 %s TEID 0x%x", upIPv6, nextULTunnel.TEID)
					} else {
						logger.CtxLog.Errorf("WNC: Invalid IP address from UL N9 interface: %v", upIP)
						return
					}
				}
			}
		}

		// WNC: Create high-precedence RS-monitor PDR for narrow ICMPv6 RS matching
		// This PDR has higher precedence than the general UL PDR to catch only RS packets
		if curDataPathNode.IsAnchorUPF() && smContext.EnableRouterSolicitationMonitor {
			hasIPv6 := smContext.SelectedPDUSessionType == nasMessage.PDUSessionTypeIPv6 ||
				smContext.SelectedPDUSessionType == nasMessage.PDUSessionTypeIPv4IPv6

			if hasIPv6 {
				logger.PduSessLog.Infof("WNC: Creating RS-monitor PDR for IPv6 session (DNN: %s, general UL PDR precedence: %d)",
					smContext.Dnn, precedence)

				// Create a new PDR specifically for RS monitoring with higher precedence
				rsPDR, err := curDataPathNode.UPF.AddPDR()
				if err != nil {
					logger.PduSessLog.Errorf("WNC: Failed to create RS-monitor PDR: %v", err)
				} else {
					// Set higher precedence (lower value) than the general UL PDR
					rsPrecedence := precedence - 1
					if rsPrecedence == 0 {
						rsPrecedence = 1 // Ensure we don't go to 0
					}
					rsPDR.Precedence = rsPrecedence

					// Copy the UL PDR's PDI as base, then add narrow SDF filter
					// IMPORTANT: Create a new PDI struct to avoid sharing with UL PDR

					// WNC: Deep-copy UE IP address and strip IPv4 fields to make RS PDR IPv6-only
					var rsUE *pfcpType.UEIPAddress
					if curULTunnel.PDR.PDI.UEIPAddress != nil {
						ue := *curULTunnel.PDR.PDI.UEIPAddress // copy struct value
						rsUE = &ue

						// Strip IPv4 fields so RS PDR is IPv6-only
						rsUE.Ipv4Address = nil
						rsUE.V4 = false
						// Keep IPv6 fields intact (V6, Ipv6Address, Ipv6PrefixDelegationBits, Ipv6d, Sd)
						logger.PduSessLog.Infof("WNC: RS PDR UEIPAddress deep-copied and stripped of IPv4 (V4=%v, V6=%v)",
							rsUE.V4, rsUE.V6)
					}

					// WNC: Deep-copy LocalFTeid to prevent edits from leaking back to UL PDR
					var rsFTeid *pfcpType.FTEID
					if curULTunnel.PDR.PDI.LocalFTeid != nil {
						fteid := *curULTunnel.PDR.PDI.LocalFTeid // copy struct value
						rsFTeid = &fteid
					}

					rsPDR.PDI = PDI{
						SourceInterface: curULTunnel.PDR.PDI.SourceInterface,
						LocalFTeid:      rsFTeid,
						NetworkInstance: curULTunnel.PDR.PDI.NetworkInstance,
						UEIPAddress:     rsUE,
						ApplicationID:   "WNC_RS_MONITOR",
						// SDFFilter will be set below - do NOT copy from UL PDR
					}

					// WNC: Copy OuterHeaderRemoval from ULPDR so gtp5g can decap the RS packet
					// This is critical - without OHR, the kernel can't remove GTP headers and the RS is dropped
					rsPDR.OuterHeaderRemoval = curULTunnel.PDR.OuterHeaderRemoval
					if rsPDR.OuterHeaderRemoval != nil {
						logger.PduSessLog.Infof("WNC: Set RS-monitor PDR OuterHeaderRemoval to match ULPDR (description: %d)",
							rsPDR.OuterHeaderRemoval.OuterHeaderRemovalDescription)
					} else {
						logger.PduSessLog.Warnf("WNC: ULPDR has no OuterHeaderRemoval - RS PDR may not decap properly")
					}

					// Set narrow SDF filter for ICMPv6 RS only:
					// gtp5g normalizes UL filters by swapping endpoints; specify the reverse so it ends up matching fe80->ff02
					// Protocol 58 = ICMPv6, fe80::/64 = link-local source, ff02::2 = all-routers multicast
					rsFlowDesc := "permit out 58 from ff02::2 to fe80::/64"
					rsPDR.PDI.SDFFilter = &pfcpType.SDFFilter{
						Bid:                     false,
						Fl:                      false,
						Spi:                     false,
						Ttc:                     false,
						Fd:                      true,
						LengthOfFlowDescription: uint16(len(rsFlowDesc)),
						FlowDescription:         []byte(rsFlowDesc),
					}

					// Capture the auto-created FAR from AddPDR() before overwriting
					rsAutoFar := rsPDR.FAR
					logger.PduSessLog.Infof("WNC: AddPDR auto-created FAR %d for RS PDR, will remove it to prevent leak", rsAutoFar.FARID)

					// Reuse the same FAR as the general UL PDR (forward to core)
					rsPDR.FAR = curULTunnel.PDR.FAR

					// Remove the auto-created FAR to prevent FAR ID leak
					// Note: FARs are not tracked in PFCP session context, only in UPF farPool
					err := curDataPathNode.UPF.RemoveFAR(rsAutoFar)
					if err != nil {
						logger.PduSessLog.Warnf("WNC: Failed to remove auto-created FAR %d: %v", rsAutoFar.FARID, err)
					} else {
						logger.PduSessLog.Infof("WNC: Successfully removed auto-created FAR %d to prevent leak", rsAutoFar.FARID)
					}

					// Attach the RS-monitor URR to this PDR
					if rsMonitorUrrId, exists := smContext.UrrIdMap[RS_MONITOR_URR]; exists {
						currentUUID := curDataPathNode.UPF.UUID()
						id := getUrrIdKey(currentUUID, rsMonitorUrrId)
						if urr, ok := smContext.UrrUpfMap[id]; ok {
							rsPDR.AppendURRs([]*URR{urr})
							logger.PduSessLog.Infof("WNC: Created RS-monitor PDR %d (precedence %d < general %d) with SDF: %s, attached URR %d",
								rsPDR.PDRID, rsPrecedence, precedence, rsFlowDesc, rsMonitorUrrId)
							logger.PduSessLog.Infof("WNC: RS-monitor PDR will ONLY match ICMPv6 RS packets (proto 58, fe80::/64 -> ff02::2)")
							logger.PduSessLog.Infof("WNC: RS-monitor PDR ApplicationID set to: %s", rsPDR.PDI.ApplicationID)
						} else {
							logger.PduSessLog.Warnf("WNC: RS-monitor URR %d not found in UrrUpfMap for UPF %s", rsMonitorUrrId, currentUUID)
						}
					} else {
						logger.PduSessLog.Warnf("WNC: RS_MONITOR_URR not allocated in UrrIdMap")
					}

					// Add the RS-monitor PDR to the PFCP session
					if err := smContext.PutPDRtoPFCPSession(curDataPathNode.UPF.NodeID, rsPDR); err != nil {
						logger.PduSessLog.Errorf("WNC: Failed to add RS-monitor PDR to PFCP session: %v", err)
					} else {
						logger.PduSessLog.Infof("WNC: Successfully added RS-monitor PDR %d to PFCP session", rsPDR.PDRID)

						// WNC: Store RS PDR pointer in DataPathNode so PFCP state assembly can find it
						curDataPathNode.RSMonitorPDR = rsPDR
						logger.PduSessLog.Infof("WNC: Stored RS-monitor PDR %d in DataPathNode for UPF %s",
							rsPDR.PDRID, curDataPathNode.UPF.NodeID.ResolveNodeIdToIp().String())
					}
				}
			} else {
				logger.PduSessLog.Debugf("WNC: Skipping RS-monitor PDR creation - session is IPv4-only (DNN: %s)", smContext.Dnn)
			}
		}

		// Setup DownLink
		if curDLTunnel != nil {
			var iface *UPFInterfaceInfo
			DLPDR := curDLTunnel.PDR
			DLDestUPF := curDLTunnel.DestEndPoint.UPF
			if defaultQER != nil {
				DLPDR.QER = append(DLPDR.QER, defaultQER)
			}
			if ambrQER != nil && !dataPath.GBRFlow {
				DLPDR.QER = append(DLPDR.QER, ambrQER)
			}

			DLPDR.Precedence = precedence

			if curDataPathNode.IsAnchorUPF() {
				DLPDR.PDI = PDI{
					SourceInterface: pfcpType.SourceInterface{
						InterfaceValue: pfcpType.SourceInterfaceCore,
					},
					NetworkInstance: &pfcpType.NetworkInstance{
						NetworkInstance: smContext.Dnn,
						FQDNEncoding:    factory.SmfConfig.Configuration.NwInstFqdnEncoding,
					},
				}
				// WNC: Set UE IP Address for IP sessions (supports IPv4, IPv6, dual-stack)
				ipv4, hasIPv4 := smContext.PDUIPv4()
				ipv6, hasIPv6 := smContext.PDUIPv6()
				ipv6LinkLocal, hasIPv6LinkLocal := smContext.PDUIPv6LinkLocal()

				if hasIPv4 || hasIPv6 || hasIPv6LinkLocal {
					DLPDR.PDI.UEIPAddress = &pfcpType.UEIPAddress{
						V4: hasIPv4,
						V6: hasIPv6 || hasIPv6LinkLocal, // Accept both global and link-local IPv6
						Sd: true,                        // Source/Destination flag for DL
					}
					if hasIPv4 {
						DLPDR.PDI.UEIPAddress.Ipv4Address = ipv4
					}
					if hasIPv6 {
						DLPDR.PDI.UEIPAddress.Ipv6Address = ipv6
						// Only signal IPv6 prefix delegation when we actually have a prefix length
						if smContext.PDUAddressIPv6PrefixLen > 0 {
							DLPDR.PDI.UEIPAddress.Ipv6d = true // IPv6 Prefix Delegation flag
							DLPDR.PDI.UEIPAddress.Ipv6PrefixDelegationBits = smContext.PDUAddressIPv6PrefixLen
						}
					}
					// WNC: Link-local address for DL (RA, NS/NA responses, DAD)
					if hasIPv6LinkLocal {
						logger.CtxLog.Infof("WNC: DL PDR supports link-local IPv6 %s for RA/NS/NA/DAD", ipv6LinkLocal)
					}
					if hasIPv4 && hasIPv6 {
						logger.CtxLog.Infof("WNC: Set DLPDR (anchor) UEIPAddress with dual-stack IPv4 %s and IPv6 %s/%d (link-local: %s)",
							ipv4, ipv6, smContext.PDUAddressIPv6PrefixLen, ipv6LinkLocal)
					} else if hasIPv6 {
						logger.CtxLog.Infof("WNC: Set DLPDR (anchor) UEIPAddress with IPv6 %s/%d (link-local: %s)",
							ipv6, smContext.PDUAddressIPv6PrefixLen, ipv6LinkLocal)
					} else {
						logger.CtxLog.Infof("WNC: Set DLPDR (anchor) UEIPAddress with IPv4 %s", ipv4)
					}
				} else if !smContext.IsIPSession() {
					logger.CtxLog.Infof("WNC: Skipping UE IP address in DLPDR PDI (anchor) for non-IP session type 0x%02x",
						smContext.SelectedPDUSessionType)
				}
			} else {
				iface = DLDestUPF.GetInterface(models.UpInterfaceType_N9, smContext.Dnn)
				if upIP, err := iface.IP(smContext.SelectedPDUSessionType); err != nil {
					logger.CtxLog.Errorln("ActivateTunnelAndPDR failed", err)
					return
				} else {
					// WNC: Build F-TEID with correct IP version for N9 interface
					var fteid *pfcpType.FTEID
					var isIPv6Tunnel bool
					if upIPv4 := upIP.To4(); upIPv4 != nil {
						fteid = &pfcpType.FTEID{
							V4:          true,
							V6:          false,
							Ipv4Address: upIPv4,
							Teid:        curDLTunnel.TEID,
						}
						isIPv6Tunnel = false
						logger.CtxLog.Debugf("WNC: Set DLPDR (N9) F-TEID with IPv4 %s TEID 0x%x", upIPv4, curDLTunnel.TEID)
					} else if upIPv6 := upIP.To16(); upIPv6 != nil {
						fteid = &pfcpType.FTEID{
							V4:          false,
							V6:          true,
							Ipv6Address: upIPv6,
							Teid:        curDLTunnel.TEID,
						}
						isIPv6Tunnel = true
						logger.CtxLog.Debugf("WNC: Set DLPDR (N9) F-TEID with IPv6 %s TEID 0x%x", upIPv6, curDLTunnel.TEID)
					} else {
						logger.CtxLog.Errorf("WNC: Invalid IP address from N9 interface: %v", upIP)
						return
					}

					// WNC: Match outer header removal to F-TEID IP family (3GPP TS 29.244 compliance)
					if isIPv6Tunnel {
						DLPDR.OuterHeaderRemoval = &pfcpType.OuterHeaderRemoval{
							OuterHeaderRemovalDescription: pfcpType.OuterHeaderRemovalGtpUUdpIpv6,
						}
						logger.CtxLog.Debugf("WNC: Set DLPDR (N9) OuterHeaderRemoval to GTP-U/UDP/IPv6")
					} else {
						DLPDR.OuterHeaderRemoval = &pfcpType.OuterHeaderRemoval{
							OuterHeaderRemovalDescription: pfcpType.OuterHeaderRemovalGtpUUdpIpv4,
						}
						logger.CtxLog.Debugf("WNC: Set DLPDR (N9) OuterHeaderRemoval to GTP-U/UDP/IPv4")
					}

					DLPDR.PDI = PDI{
						SourceInterface: pfcpType.SourceInterface{InterfaceValue: pfcpType.SourceInterfaceCore},
						LocalFTeid:      fteid,
						NetworkInstance: &pfcpType.NetworkInstance{
							NetworkInstance: smContext.Dnn,
							FQDNEncoding:    factory.SmfConfig.Configuration.NwInstFqdnEncoding,
						},
					}
					// WNC: Set UE IP Address for IP sessions (supports IPv4, IPv6, dual-stack)
					ipv4, hasIPv4 := smContext.PDUIPv4()
					ipv6, hasIPv6 := smContext.PDUIPv6()
					ipv6LinkLocal, hasIPv6LinkLocal := smContext.PDUIPv6LinkLocal()

					if hasIPv4 || hasIPv6 || hasIPv6LinkLocal {
						DLPDR.PDI.UEIPAddress = &pfcpType.UEIPAddress{
							V4: hasIPv4,
							V6: hasIPv6 || hasIPv6LinkLocal, // Accept both global and link-local IPv6
							Sd: true,                        // Source/Destination flag for DL
						}
						if hasIPv4 {
							DLPDR.PDI.UEIPAddress.Ipv4Address = ipv4
						}
						if hasIPv6 {
							DLPDR.PDI.UEIPAddress.Ipv6Address = ipv6
							// Only signal IPv6 prefix delegation when we actually have a prefix length
							if smContext.PDUAddressIPv6PrefixLen > 0 {
								DLPDR.PDI.UEIPAddress.Ipv6d = true // IPv6 Prefix Delegation flag
								DLPDR.PDI.UEIPAddress.Ipv6PrefixDelegationBits = smContext.PDUAddressIPv6PrefixLen
							}
						}
						// WNC: Link-local address for DL N9 (RA, NS/NA responses, DAD)
						if hasIPv6LinkLocal {
							logger.CtxLog.Infof("WNC: DL PDR (N9) supports link-local IPv6 %s for RA/NS/NA/DAD", ipv6LinkLocal)
						}
						if hasIPv4 && hasIPv6 {
							logger.CtxLog.Infof("WNC: Set DLPDR (N9) UEIPAddress with dual-stack IPv4 %s and IPv6 %s/%d (link-local: %s)",
								ipv4, ipv6, smContext.PDUAddressIPv6PrefixLen, ipv6LinkLocal)
						} else if hasIPv6 {
							logger.CtxLog.Infof("WNC: Set DLPDR (N9) UEIPAddress with IPv6 %s/%d (link-local: %s)",
								ipv6, smContext.PDUAddressIPv6PrefixLen, ipv6LinkLocal)
						} else {
							logger.CtxLog.Infof("WNC: Set DLPDR (N9) UEIPAddress with IPv4 %s", ipv4)
						}
					} else if !smContext.IsIPSession() {
						logger.CtxLog.Infof("WNC: Skipping UE IP address in DLPDR PDI (N9) for non-IP session type 0x%02x",
							smContext.SelectedPDUSessionType)
					}
				}
			}

			DLFAR := DLPDR.FAR

			logger.PduSessLog.Traceln("Current DP Node IP: ", curDataPathNode.UPF.NodeID.ResolveNodeIdToIp().String())
			logger.PduSessLog.Traceln("Before DLPDR OuterHeaderCreation")
			if nextDLDest := curDataPathNode.Prev(); nextDLDest != nil {
				logger.PduSessLog.Traceln("In DLPDR OuterHeaderCreation")
				nextDLTunnel := nextDLDest.DownLinkTunnel
				// If the flow is disable, the tunnel and the session rules will not be created

				DLFAR.ApplyAction = pfcpType.ApplyAction{
					Buff: false,
					Drop: false,
					Dupl: false,
					Forw: true,
					Nocp: false,
				}

				iface = nextDLDest.UPF.GetInterface(models.UpInterfaceType_N9, smContext.Dnn)

				if upIP, err := iface.IP(smContext.SelectedPDUSessionType); err != nil {
					logger.CtxLog.Errorln("ActivateTunnelAndPDR failed", err)
					return
				} else {
					// WNC: Build Outer Header Creation with correct IP version for DL N9
					var outerHeaderCreation *pfcpType.OuterHeaderCreation
					if upIPv4 := upIP.To4(); upIPv4 != nil {
						outerHeaderCreation = &pfcpType.OuterHeaderCreation{
							OuterHeaderCreationDescription: pfcpType.OuterHeaderCreationGtpUUdpIpv4,
							Ipv4Address:                    upIPv4,
							Teid:                           nextDLTunnel.TEID,
						}
						logger.CtxLog.Debugf("WNC: Set DLFAR N9 OuterHeader with IPv4 %s TEID 0x%x", upIPv4, nextDLTunnel.TEID)
					} else if upIPv6 := upIP.To16(); upIPv6 != nil {
						outerHeaderCreation = &pfcpType.OuterHeaderCreation{
							OuterHeaderCreationDescription: pfcpType.OuterHeaderCreationGtpUUdpIpv6,
							Ipv6Address:                    upIPv6,
							Teid:                           nextDLTunnel.TEID,
						}
						logger.CtxLog.Debugf("WNC: Set DLFAR N9 OuterHeader with IPv6 %s TEID 0x%x", upIPv6, nextDLTunnel.TEID)
					} else {
						logger.CtxLog.Errorf("WNC: Invalid IP address from DL N9 interface: %v", upIP)
						return
					}

					DLFAR.ForwardingParameters = &ForwardingParameters{
						DestinationInterface: pfcpType.DestinationInterface{InterfaceValue: pfcpType.DestinationInterfaceAccess},
						OuterHeaderCreation:  outerHeaderCreation,
					}
				}
			} else {
				ANUPF := dataPath.FirstDPNode
				DLPDR = ANUPF.DownLinkTunnel.PDR
				DLFAR = DLPDR.FAR
				DLFAR.ForwardingParameters = new(ForwardingParameters)
				DLFAR.ForwardingParameters.DestinationInterface.InterfaceValue = pfcpType.DestinationInterfaceAccess

				if anIP := smContext.Tunnel.ANInformation.IPAddress; anIP != nil {
					DLFAR.ForwardingParameters.NetworkInstance = &pfcpType.NetworkInstance{
						NetworkInstance: smContext.Dnn,
						FQDNEncoding:    factory.SmfConfig.Configuration.NwInstFqdnEncoding,
					}
					DLFAR.ForwardingParameters.OuterHeaderCreation = new(pfcpType.OuterHeaderCreation)

					dlOuterHeaderCreation := DLFAR.ForwardingParameters.OuterHeaderCreation
					dlOuterHeaderCreation.OuterHeaderCreationDescription = pfcpType.OuterHeaderCreationGtpUUdpIpv4
					dlOuterHeaderCreation.Teid = smContext.Tunnel.ANInformation.TEID
					dlOuterHeaderCreation.Ipv4Address = smContext.Tunnel.ANInformation.IPAddress.To4()
				}
			}
		}
	}

	dataPath.Activated = true
}

func (dataPath *DataPath) DeactivateTunnelAndPDR(smContext *SMContext) {
	firstDPNode := dataPath.FirstDPNode

	var targetNodes []*DataPathNode
	for node := firstDPNode; node != nil; node = node.Next() {
		targetNodes = append(targetNodes, node)
	}
	// Deactivate Tunnels
	for _, node := range targetNodes {
		node.DeactivateUpLinkTunnel(smContext)
		node.DeactivateDownLinkTunnel(smContext)
		// WNC: Also deactivate RS-monitor PDR if it exists
		node.DeactivateRSMonitorPDR(smContext)
	}

	// WNC: Free the global RS_MONITOR_URR ID exactly once per session
	// (DeactivateRSMonitorPDR runs per-node, so we do this here instead)
	// Only free if the ID was actually allocated (non-zero) to prevent corrupting UrrIDGenerator
	if rsMonitorUrrId, exists := smContext.UrrIdMap[RS_MONITOR_URR]; exists && rsMonitorUrrId != 0 {
		// Free the URR ID back to the session-level ID generator
		smContext.UrrIDGenerator.FreeID(int64(rsMonitorUrrId))
		logger.CtxLog.Infof("WNC: Freed RS_MONITOR_URR ID %d back to session UrrIDGenerator", rsMonitorUrrId)

		// Remove from UrrIdMap
		delete(smContext.UrrIdMap, RS_MONITOR_URR)
		logger.CtxLog.Infof("WNC: Removed RS_MONITOR_URR (ID %d) from UrrIdMap", rsMonitorUrrId)
	} else if exists && rsMonitorUrrId == 0 {
		// IPv4-only session or session where RS monitoring was never enabled
		logger.CtxLog.Debugf("WNC: Skipping RS_MONITOR_URR cleanup - ID is 0 (never allocated)")
		delete(smContext.UrrIdMap, RS_MONITOR_URR)
	}

	dataPath.Activated = false
}

func (p *DataPath) RemovePDR() {
	for curDPNode := p.FirstDPNode; curDPNode != nil; curDPNode = curDPNode.Next() {
		if curDPNode.DownLinkTunnel != nil && curDPNode.DownLinkTunnel.PDR != nil {
			curDPNode.DownLinkTunnel.PDR.State = RULE_REMOVE
			curDPNode.DownLinkTunnel.PDR.FAR.State = RULE_REMOVE
		}
		if curDPNode.UpLinkTunnel != nil && curDPNode.UpLinkTunnel.PDR != nil {
			curDPNode.UpLinkTunnel.PDR.State = RULE_REMOVE
			curDPNode.UpLinkTunnel.PDR.FAR.State = RULE_REMOVE
		}
		// WNC: Mark RS-monitor PDR for removal if it exists
		// This ensures PreRemoveDataPath() will send RemovePDR during PFCP Session Modification
		if curDPNode.RSMonitorPDR != nil {
			curDPNode.RSMonitorPDR.State = RULE_REMOVE
			logger.CtxLog.Infof("WNC: Marked RS-monitor PDR %d for removal (state=RULE_REMOVE)", curDPNode.RSMonitorPDR.PDRID)
			// Mark the shared FAR for removal as well (it's shared with UL PDR)
			if curDPNode.RSMonitorPDR.FAR != nil {
				curDPNode.RSMonitorPDR.FAR.State = RULE_REMOVE
				logger.CtxLog.Infof("WNC: Marked RS-monitor PDR's FAR %d for removal (shared with UL PDR)", curDPNode.RSMonitorPDR.FAR.FARID)
			}
		}
	}
}

func (p *DataPath) GetChargingUrr(smContext *SMContext) []*URR {
	var chargingUrrs []*URR
	var urrs []*URR

	for node := p.FirstDPNode; node != nil; node = node.Next() {
		// Charging rules only apply to anchor UPF
		// Note: ULPDR and DLPDR share the same URR but have different FAR
		// See AddChargingRules() for more details
		if node.IsAnchorUPF() {
			if node.UpLinkTunnel != nil && node.UpLinkTunnel.PDR != nil {
				urrs = node.UpLinkTunnel.PDR.URR
			} else if node.DownLinkTunnel != nil && node.DownLinkTunnel.PDR != nil {
				urrs = node.DownLinkTunnel.PDR.URR
			}

			for _, urr := range urrs {
				if smContext.ChargingInfo[urr.URRID] != nil {
					chargingUrrs = append(chargingUrrs, urr)
				}
			}
		}
	}

	return chargingUrrs
}

func (p *DataPath) AddChargingRules(smContext *SMContext, chgLevel ChargingLevel, chgData *models.ChargingData) {
	logger.ChargingLog.Tracef("AddChargingRules: type[%v], data:[%+v]", chgLevel, chgData)
	if chgData == nil {
		return
	}

	for node := p.FirstDPNode; node != nil; node = node.Next() {
		// Charging rules only apply to anchor UPF
		if node.IsAnchorUPF() {
			var urr *URR
			chgInfo := &ChargingInfo{
				RatingGroup:   chgData.RatingGroup,
				ChargingLevel: chgLevel,
				UpfId:         node.UPF.UUID(),
			}

			urrId, err := smContext.UrrIDGenerator.Allocate()
			if err != nil {
				logger.PduSessLog.Errorln("Generate URR Id failed")
				return
			}

			currentUUID := node.UPF.UUID()
			id := getUrrIdKey(currentUUID, uint32(urrId))

			if oldURR, ok := smContext.UrrUpfMap[id]; !ok {
				// For online charging, the charging trigger "Start of the Service data flow" are needed.
				// Therefore, the START reporting trigger in the urr are needed to detect the Start of the SDF
				if chgData.Online {
					if newURR, err2 := node.UPF.AddURR(uint32(urrId),
						NewMeasureInformation(false, false),
						SetStartOfSDFTrigger()); err2 != nil {
						logger.PduSessLog.Errorln("new URR failed")
						return
					} else {
						urr = newURR
					}

					chgInfo.ChargingMethod = models.QuotaManagementIndicator_ONLINE_CHARGING
				} else if chgData.Offline {
					// For offline charging, URR only need to report based on the volume threshold
					if newURR, err2 := node.UPF.AddURR(uint32(urrId),
						NewMeasureInformation(false, false),
						NewVolumeThreshold(smContext.UrrReportThreshold)); err2 != nil {
						logger.PduSessLog.Errorln("new URR failed")
						return
					} else {
						urr = newURR
					}

					chgInfo.ChargingMethod = models.QuotaManagementIndicator_OFFLINE_CHARGING
				}
				smContext.UrrUpfMap[id] = urr
			} else {
				urr = oldURR
			}

			if urr != nil {
				logger.PduSessLog.Tracef("Successfully add URR %d for Rating group %d", urr.URRID, chgData.RatingGroup)

				smContext.ChargingInfo[urr.URRID] = chgInfo
				if node.UpLinkTunnel != nil && node.UpLinkTunnel.PDR != nil {
					if !isUrrExist(node.UpLinkTunnel.PDR.URR, urr) {
						node.UpLinkTunnel.PDR.AppendURRs([]*URR{urr})
						// nolint
						nodeId, _ := node.GetUPFID()
						logger.PduSessLog.Tracef("UpLinkTunnel add URR for node %s %+v",
							nodeId, node.UpLinkTunnel.PDR)
					}
				}
				if node.DownLinkTunnel != nil && node.DownLinkTunnel.PDR != nil {
					if !isUrrExist(node.DownLinkTunnel.PDR.URR, urr) {
						node.DownLinkTunnel.PDR.AppendURRs([]*URR{urr})
						// nolint
						nodeId, _ := node.GetUPFID()
						logger.PduSessLog.Tracef("DownLinkTunnel add URR for node %s %+v",
							nodeId, node.DownLinkTunnel.PDR)
					}
				}
			}
		}
	}
}

func (p *DataPath) AddQoS(smContext *SMContext, qfi uint8, qos *models.QosData) {
	// QFI = 1 -> default QFI
	if qos == nil && qfi != 1 {
		return
	}
	for node := p.FirstDPNode; node != nil; node = node.Next() {
		var qer *QER

		currentUUID := node.UPF.GetUUID()
		id := getQosIdKey(currentUUID, qfi)

		if qerId, ok := smContext.QerUpfMap[id]; !ok {
			if newQER, err := node.UPF.AddQER(); err != nil {
				logger.PduSessLog.Errorln("new QER failed")
				return
			} else {
				newQER.QFI = pfcpType.QFI{
					QFI: qfi,
				}
				newQER.GateStatus = &pfcpType.GateStatus{
					ULGate: pfcpType.GateOpen,
					DLGate: pfcpType.GateOpen,
				}
				if isGBRFlow(qos) {
					var bitRateKbpsQoSGBRUL uint64
					var bitRateKbpsQoSGBRDL uint64
					var bitRateKbpsQoSMBRUL uint64
					var bitRateKbpsQoSMBRDL uint64
					var bitRateConvertErr error
					bitRateKbpsQoSGBRUL, bitRateConvertErr = util.BitRateTokbps(qos.GbrUl)
					if bitRateConvertErr != nil {
						logger.PduSessLog.Panicln("Cannot get the unit of GBRUL, please check the settings in web console")
						return
					}

					bitRateKbpsQoSGBRDL, bitRateConvertErr = util.BitRateTokbps(qos.GbrDl)
					if bitRateConvertErr != nil {
						logger.PduSessLog.Panicln("Cannot get the unit of GBRDL, please check the settings in web console")
						return
					}

					bitRateKbpsQoSMBRUL, bitRateConvertErr = util.BitRateTokbps(qos.MaxbrUl)
					if bitRateConvertErr != nil {
						logger.PduSessLog.Panicln("Cannot get the unit of MBRUL, please check the settings in web console")
						return
					}

					bitRateKbpsQoSMBRDL, bitRateConvertErr = util.BitRateTokbps(qos.MaxbrDl)
					if bitRateConvertErr != nil {
						logger.PduSessLog.Panicln("Cannot get the unit of MBRDL, please check the settings in web console")
						return
					}

					newQER.GBR = &pfcpType.GBR{
						ULGBR: bitRateKbpsQoSGBRUL,
						DLGBR: bitRateKbpsQoSGBRDL,
					}
					newQER.MBR = &pfcpType.MBR{
						ULMBR: bitRateKbpsQoSMBRUL,
						DLMBR: bitRateKbpsQoSMBRDL,
					}
				} else {
					var bitRateKbpsSessionAmbrMBRUL uint64
					var bitRateKbpsSessionAmbrMBRDL uint64
					var bitRateConvertErr error
					bitRateKbpsSessionAmbrMBRUL, bitRateConvertErr = util.BitRateTokbps(qos.MaxbrUl)
					if bitRateConvertErr != nil {
						logger.PduSessLog.Error("Cannot get the unit of MBRUL, please check the settings in web console")
						return
					}
					bitRateKbpsSessionAmbrMBRDL, bitRateConvertErr = util.BitRateTokbps(qos.MaxbrDl)

					if bitRateConvertErr != nil {
						logger.PduSessLog.Error("Cannot get the unit of MBRDL, please check the settings in web console")
						return
					}
					// Non-GBR flow should follows session-AMBR
					newQER.MBR = &pfcpType.MBR{
						ULMBR: bitRateKbpsSessionAmbrMBRUL,
						DLMBR: bitRateKbpsSessionAmbrMBRDL,
					}
				}
				qer = newQER
			}
			smContext.QerUpfMap[id] = qer.QERID
		} else if oldQER := node.UPF.GetQERById(qerId); ok {
			if oldQER != nil {
				qer = oldQER
			}
		}
		if qer != nil {
			if node.UpLinkTunnel != nil && node.UpLinkTunnel.PDR != nil {
				node.UpLinkTunnel.PDR.QER = append(node.UpLinkTunnel.PDR.QER, qer)
			}
			if node.DownLinkTunnel != nil && node.DownLinkTunnel.PDR != nil {
				node.DownLinkTunnel.PDR.QER = append(node.DownLinkTunnel.PDR.QER, qer)
			}
		}
	}
}

func (p *DataPath) UpdateFlowDescription(ulFlowDesc, dlFlowDesc string) {
	// WNC: Replace "assigned" keyword with actual UE IP address for wildcard matching
	// This enables Open5GS-style catch-all PDRs: "permit out ip from assigned to any"
	// The UE IP will be extracted from the PDR's UEIPAddress field during PFCP message building
	// For dual-stack sessions, the UPF will handle emitting both IPv4 and IPv6 selectors

	for curDPNode := p.FirstDPNode; curDPNode != nil; curDPNode = curDPNode.Next() {
		// Downlink: "permit out ip from any to assigned" -> match packets TO the UE
		curDPNode.DownLinkTunnel.PDR.PDI.SDFFilter = &pfcpType.SDFFilter{
			Bid:                     false,
			Fl:                      false,
			Spi:                     false,
			Ttc:                     false,
			Fd:                      true,
			LengthOfFlowDescription: uint16(len(dlFlowDesc)),
			FlowDescription:         []byte(dlFlowDesc),
		}

		// Uplink: "permit out ip from assigned to any" -> match packets FROM the UE
		curDPNode.UpLinkTunnel.PDR.PDI.SDFFilter = &pfcpType.SDFFilter{
			Bid:                     false,
			Fl:                      false,
			Spi:                     false,
			Ttc:                     false,
			Fd:                      true,
			LengthOfFlowDescription: uint16(len(ulFlowDesc)),
			FlowDescription:         []byte(ulFlowDesc),
		}

		logger.PduSessLog.Debugf("WNC: Set SDF filters - UL: %s, DL: %s", ulFlowDesc, dlFlowDesc)
	}
}

func (p *DataPath) AddForwardingParameters(fwdPolicyID string, teid uint32) {
	for curDPNode := p.FirstDPNode; curDPNode != nil; curDPNode = curDPNode.Next() {
		if curDPNode.IsAnchorUPF() {
			curDPNode.UpLinkTunnel.PDR.FAR.ForwardingParameters.ForwardingPolicyID = fwdPolicyID
			// TODO: Support the RouteInfo in targetTraRouting
			// TODO: Check the message is only presents one of RouteInfo or RouteProfId and sends failure message to the PCF
			// } else if routeInfo := targetTraRouting.RouteInfo; routeInfo != nil {
			// 	locToRouteIP := net.ParseIP(routeInfo.Ipv4Addr)
			// 	curDPNode.UpLinkTunnel.PDR.FAR.ForwardingParameters.OuterHeaderCreation = &pfcpType.OuterHeaderCreation{
			// 		OuterHeaderCreationDescription: pfcpType.OuterHeaderCreationUdpIpv4,
			// 		Ipv4Address:                    locToRouteIP,
			// 		PortNumber:                     uint16(routeInfo.PortNumber),
			// 	}
			// }
		}
		// get old TEID
		// TODO: remove this if RAN tunnel issue is fixed, because the AN tunnel is only one
		if curDPNode.IsANUPF() {
			curDPNode.UpLinkTunnel.PDR.PDI.LocalFTeid.Teid = teid
		}
	}
}

func (dataPath *DataPath) CopyFirstDPNode() *DataPathNode {
	if dataPath.FirstDPNode == nil {
		return nil
	}
	var firstNode *DataPathNode = nil
	var parentNode *DataPathNode = nil
	for node := dataPath.FirstDPNode; node != nil; node = node.Next() {
		newNode := NewDataPathNode()
		if firstNode == nil {
			firstNode = newNode
		}
		newNode.UPF = node.UPF
		if parentNode != nil {
			newNode.AddPrev(parentNode)
			parentNode.AddNext(newNode)
		}
		parentNode = newNode
	}
	return firstNode
}

func getQosIdKey(uuid uuid.UUID, qfi uint8) string {
	return uuid.String() + ":" + strconv.Itoa(int(qfi))
}

func isGBRFlow(qos *models.QosData) bool {
	if qos == nil {
		return false
	}
	_, ok := standardGbr5QIs[qos.Var5qi]
	return ok
}
