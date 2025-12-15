package handler

import (
	"fmt"
	"net"
	"strconv"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/pfcp/pfcpUdp"
	smf_context "github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/logger"
	pfcp_message "github.com/free5gc/smf/internal/pfcp/message"
	"github.com/free5gc/smf/pkg/service"
)

func HandlePfcpHeartbeatRequest(msg *pfcpUdp.Message) {
	h := msg.PfcpMessage.Header
	pfcp_message.SendHeartbeatResponse(msg.RemoteAddr, h.SequenceNumber)
}

func HandlePfcpPfdManagementRequest(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP PFD Management Request handling is not implemented")
}

// WNC: Enhanced to parse UserPlaneIPResourceInformation from UPF and update interface addresses
func HandlePfcpAssociationSetupRequest(msg *pfcpUdp.Message) {
	req := msg.PfcpMessage.Body.(pfcp.PFCPAssociationSetupRequest)

	nodeID := req.NodeID
	if nodeID == nil {
		logger.PfcpLog.Errorln("pfcp association needs NodeID")
		return
	}
	logger.PfcpLog.Infof("Handle PFCP Association Setup Request with NodeID[%s]",
		nodeID.ResolveNodeIdToIp().String())

	upf := smf_context.RetrieveUPFNodeByNodeID(*nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		return
	}

	// WNC: Extract IPv6 capability from UPF Function Features (3GPP TS 29.244)
	// Bit 0 of SupportedFeatures indicates IPv6 support in gtp5g
	if req.UPFunctionFeatures != nil {
		upf.SupportsIPv6 = (req.UPFunctionFeatures.SupportedFeatures & 0x01) != 0
		logger.PfcpLog.Infof("WNC: UPF[%s] IPv6 support: %v (features: 0x%x)",
			nodeID.ResolveNodeIdToIp().String(), upf.SupportsIPv6,
			req.UPFunctionFeatures.SupportedFeatures)
	} else {
		// WNC: Default to false if no UPF Function Features provided
		upf.SupportsIPv6 = false
		logger.PfcpLog.Warnf("WNC: UPF[%s] did not provide UPF Function Features, assuming no IPv6 support",
			nodeID.ResolveNodeIdToIp().String())
	}

	// WNC: CRITICAL - Parse UserPlaneIPResourceInformation advertised by UPF via PFCP
	// This contains the actual N3/N9 interface addresses (IPv4/IPv6) that the UPF is using
	// Previously this was IGNORED, causing SMF to rely only on static smfcfg.yaml config
	if req.UserPlaneIPResourceInformation != nil {
		upIpResInfo := req.UserPlaneIPResourceInformation

		logger.PfcpLog.Infof("WNC: UPF[%s] advertised UserPlaneIPResourceInformation - V4: %v, V6: %v, "+
			"IPv4: %v, IPv6: %v, NetworkInstance: %s, SourceInterface: %d",
			nodeID.ResolveNodeIdToIp().String(),
			upIpResInfo.V4, upIpResInfo.V6,
			upIpResInfo.Ipv4Address, upIpResInfo.Ipv6Address,
			upIpResInfo.NetworkInstance.NetworkInstance, upIpResInfo.SourceInterface)

		// WNC: Log what we received for dual-stack troubleshooting
		if upIpResInfo.V4 && upIpResInfo.Ipv4Address != nil {
			logger.PfcpLog.Infof("WNC: UPF[%s] PFCP advertised IPv4 address: %s",
				nodeID.ResolveNodeIdToIp().String(), upIpResInfo.Ipv4Address.String())
		} else {
			logger.PfcpLog.Warnf("WNC: UPF[%s] PFCP did NOT advertise IPv4 address (V4 flag: %v)",
				nodeID.ResolveNodeIdToIp().String(), upIpResInfo.V4)
		}

		if upIpResInfo.V6 && upIpResInfo.Ipv6Address != nil {
			logger.PfcpLog.Infof("WNC: UPF[%s] PFCP advertised IPv6 address: %s",
				nodeID.ResolveNodeIdToIp().String(), upIpResInfo.Ipv6Address.String())
		} else {
			logger.PfcpLog.Warnf("WNC: UPF[%s] PFCP did NOT advertise IPv6 address (V6 flag: %v) - "+
				"This explains why IPv6EndPointAddresses count is 0!",
				nodeID.ResolveNodeIdToIp().String(), upIpResInfo.V6)
		}

		// WNC: Determine interface type from SourceInterface field (3GPP TS 29.244)
		// 0 = Access (N3), 1 = Core (N9), 2 = SGi-LAN/N6, 3 = CP-function
		var interfaceTypeStr string
		switch upIpResInfo.SourceInterface {
		case 0:
			interfaceTypeStr = "N3 (Access)"
			logger.PfcpLog.Debugf("WNC: UPF[%s] PFCP interface is N3 (Access)", nodeID.ResolveNodeIdToIp().String())
		case 1:
			interfaceTypeStr = "N9 (Core)"
			logger.PfcpLog.Debugf("WNC: UPF[%s] PFCP interface is N9 (Core)", nodeID.ResolveNodeIdToIp().String())
		default:
			interfaceTypeStr = fmt.Sprintf("Unknown(%d)", upIpResInfo.SourceInterface)
			logger.PfcpLog.Warnf("WNC: UPF[%s] PFCP unknown SourceInterface: %d, defaulting to N3",
				nodeID.ResolveNodeIdToIp().String(), upIpResInfo.SourceInterface)
		}
		logger.PfcpLog.Infof("WNC: UPF[%s] PFCP interface type: %s", nodeID.ResolveNodeIdToIp().String(), interfaceTypeStr)

		// WNC: TODO - Update UPF interface information from PFCP message
		// This requires adding a method to update UPF.N3Interfaces/N9Interfaces
		// For now, we log the discrepancy so operators can see if PFCP differs from YAML config
		logger.PfcpLog.Infof("WNC: UPF[%s] PFCP vs Config comparison - "+
			"Current N3 interfaces in SMF context: %d, Current N9 interfaces: %d",
			nodeID.ResolveNodeIdToIp().String(), len(upf.N3Interfaces), len(upf.N9Interfaces))

	} else {
		logger.PfcpLog.Warnf("WNC: UPF[%s] did NOT provide UserPlaneIPResourceInformation in PFCP Association Setup Request! "+
			"SMF will rely entirely on static smfcfg.yaml configuration. "+
			"This may explain missing IPv6 addresses if UPF's PFCP stack (go-gtp5gnl) doesn't send them.",
			nodeID.ResolveNodeIdToIp().String())
	}

	// WNC: Response with PFCP Association Setup Response
	cause := pfcpType.Cause{
		CauseValue: pfcpType.CauseRequestAccepted,
	}
	pfcp_message.SendPfcpAssociationSetupResponse(msg.RemoteAddr, cause)
}

func HandlePfcpAssociationUpdateRequest(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP Association Update Request handling is not implemented")
}

func HandlePfcpAssociationReleaseRequest(msg *pfcpUdp.Message) {
	pfcpMsg := msg.PfcpMessage.Body.(pfcp.PFCPAssociationReleaseRequest)

	var cause pfcpType.Cause
	upf := smf_context.RetrieveUPFNodeByNodeID(*pfcpMsg.NodeID)

	if upf != nil {
		smf_context.RemoveUPFNodeByNodeID(*pfcpMsg.NodeID)
		cause.CauseValue = pfcpType.CauseRequestAccepted
	} else {
		cause.CauseValue = pfcpType.CauseNoEstablishedPfcpAssociation
	}

	pfcp_message.SendPfcpAssociationReleaseResponse(msg.RemoteAddr, cause)
}

func HandlePfcpNodeReportRequest(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP Node Report Request handling is not implemented")
}

func HandlePfcpSessionSetDeletionRequest(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP Session Set Deletion Request handling is not implemented")
}

func HandlePfcpSessionSetDeletionResponse(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP Session Set Deletion Response handling is not implemented")
}

func HandlePfcpSessionReportRequest(msg *pfcpUdp.Message) {
	var cause pfcpType.Cause

	req := msg.PfcpMessage.Body.(pfcp.PFCPSessionReportRequest)
	SEID := msg.PfcpMessage.Header.SEID
	smContext := smf_context.GetSMContextBySEID(SEID)
	seqFromUPF := msg.PfcpMessage.Header.SequenceNumber

	if smContext == nil {
		logger.PfcpLog.Errorf("PFCP Session SEID[%d] not found", SEID)
		cause.CauseValue = pfcpType.CauseSessionContextNotFound
		pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, seqFromUPF, 0)
		return
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
	upfNodeIDtoIP := upfNodeID.ResolveNodeIdToIp()
	if upfNodeIDtoIP.IsUnspecified() {
		logger.PduSessLog.Errorf("Invalid PFCP Session Report Request : no PFCP session found with SEID %d", SEID)
		cause.CauseValue = pfcpType.CauseNoEstablishedPfcpAssociation
		pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, seqFromUPF, 0)
		return
	}
	upfNodeIDtoIPStr := upfNodeIDtoIP.String()

	pfcpCtx := smContext.PFCPContext[upfNodeIDtoIPStr]
	if pfcpCtx == nil {
		logger.PfcpLog.Errorf("pfcpCtx [nodeId: %v, seid:%d] not found", upfNodeID, SEID)
		cause.CauseValue = pfcpType.CauseNoEstablishedPfcpAssociation
		pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, seqFromUPF, 0)
		return
	}
	remoteSEID := pfcpCtx.RemoteSEID

	upf := smf_context.RetrieveUPFNodeByNodeID(upfNodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can't find UPF[%s]", upfNodeIDtoIPStr)
		cause.CauseValue = pfcpType.CauseNoEstablishedPfcpAssociation
		pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, seqFromUPF, 0)
		return
	}
	if err := upf.IsAssociated(); err != nil {
		logger.PfcpLog.Warnf("PFCP Session Report Request rejected: %+v", err)
		cause.CauseValue = pfcpType.CauseNoEstablishedPfcpAssociation
		pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, seqFromUPF, 0)
	}

	if smContext.UpCnxState == models.UpCnxState_DEACTIVATED {
		if req.ReportType.Dldr {
			downlinkDataReport := req.DownlinkDataReport

			if downlinkDataReport.DownlinkDataServiceInformation != nil {
				logger.PfcpLog.Warnf(
					"PFCP Session Report Request DownlinkDataServiceInformation handling is not implemented")
			}

			n1n2Request := models.N1N2MessageTransferRequest{}

			// TS 23.502 4.2.3.3 3a. Send Namf_Communication_N1N2MessageTransfer Request, SMF->AMF
			if n2SmBuf, err := smf_context.BuildPDUSessionResourceSetupRequestTransfer(smContext); err != nil {
				logger.PduSessLog.Errorln("Build PDUSessionResourceSetupRequestTransfer failed:", err)
			} else {
				n1n2Request.BinaryDataN2Information = n2SmBuf
			}

			n1n2Request.JsonData = &models.N1N2MessageTransferReqData{
				PduSessionId: smContext.PDUSessionID,
				// Temporarily assign SMF itself,
				// TODO: TS 23.502 4.2.3.3 5. Namf_Communication_N1N2TransferFailureNotification
				N1n2FailureTxfNotifURI: fmt.Sprintf("%s://%s",
					smf_context.GetSelf().URIScheme,
					net.JoinHostPort(smf_context.GetSelf().RegisterIPv4, strconv.Itoa(int(smf_context.GetSelf().SBIPort)))),
				N2InfoContainer: &models.N2InfoContainer{
					N2InformationClass: models.N2InformationClass_SM,
					SmInfo: &models.N2SmInformation{
						PduSessionId: smContext.PDUSessionID,
						N2InfoContent: &models.N2InfoContent{
							NgapIeType: models.AmfCommunicationNgapIeType_PDU_RES_SETUP_REQ,
							NgapData: &models.RefToBinaryData{
								ContentId: "N2SmInformation",
							},
						},
						SNssai: smContext.SNssai,
					},
				},
			}

			ctx, _, errToken := smf_context.GetSelf().GetTokenCtx(models.ServiceName_NAMF_COMM, models.NrfNfManagementNfType_AMF)
			if errToken != nil {
				logger.PfcpLog.Warnf("Get NAMF_COMM context failed: %s", errToken)
				return
			}
			rspData, err := service.GetApp().Consumer().
				N1N2MessageTransfer(ctx, smContext.Supi, n1n2Request, smContext.CommunicationClientApiPrefix)
			if err != nil {
				logger.ConsumerLog.Warnf("Send N1N2Transfer failed: %s", err)
				return
			}

			if rspData.Cause == models.N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE {
				logger.PfcpLog.Infof("Receive %v, AMF is able to page the UE", rspData.Cause)
			}
			if rspData.Cause == models.N1N2MessageTransferCause_UE_NOT_RESPONDING {
				logger.PfcpLog.Warnf("%v", rspData.Cause)
				// TODO: TS 23.502 4.2.3.3 3c. Failure indication
			}
		}
	}

	if req.ReportType.Usar && req.UsageReport != nil {
		smContext.HandleReports(req.UsageReport, nil, nil, upfNodeID, "")
		// After receiving the Usage Report, it should send charging request to the CHF
		// and update the URR with the quota or other charging information according to
		// the charging response
		service.GetApp().Processor().ReportUsageAndUpdateQuota(smContext)
	}

	// WNC: Handle Event Reporting for Router Solicitation (Phase 3)
	// Check for Eveth trigger in usage reports (kernel sends USAR_TRIGGER_EVETH)
	if req.UsageReport != nil {
		for _, usageReport := range req.UsageReport {
			// WNC: Log raw trigger flags received by SMF from PFCP Session Report Request
			if usageReport.UsageReportTrigger != nil && usageReport.URRID != nil {
				// WNC: Marshal the UsageReportTrigger to get the raw PFCP octets
				if raw, err := usageReport.UsageReportTrigger.MarshalBinary(); err == nil && len(raw) >= 3 {
					logger.PfcpLog.Infof("WNC: SMF decoded UsageReportTrigger octets [%02x %02x %02x] (expect oct6 bit 0x80 for Eveth, Eveth=%v Perio=%v Volth=%v Volqu=%v) URR=%d",
						raw[0], raw[1], raw[2],
						usageReport.UsageReportTrigger.Eveth,
						usageReport.UsageReportTrigger.Perio,
						usageReport.UsageReportTrigger.Volth,
						usageReport.UsageReportTrigger.Volqu,
						usageReport.URRID.UrrIdValue)
				} else {
					// Fallback if MarshalBinary fails
					logger.PfcpLog.Infof("WNC: SMF received UsageReport URR=%d trigger (Eveth=%v Perio=%v Volth=%v Volqu=%v)",
						usageReport.URRID.UrrIdValue,
						usageReport.UsageReportTrigger.Eveth,
						usageReport.UsageReportTrigger.Perio,
						usageReport.UsageReportTrigger.Volth,
						usageReport.UsageReportTrigger.Volqu)
				}
			}
			// WNC: Check if this is an event-triggered report (Eveth bit set)
			if usageReport.UsageReportTrigger != nil && usageReport.UsageReportTrigger.Eveth {
				// WNC: Verify this is the RS_MONITOR_URR by comparing URR ID
				if usageReport.URRID != nil {
					urrID := usageReport.URRID.UrrIdValue
					rsMonitorUrrId, exists := smContext.UrrIdMap[smf_context.RS_MONITOR_URR]

					if exists && urrID == rsMonitorUrrId {
						logger.PfcpLog.Infof("WNC: Router Solicitation event received for SEID %d, URR %d", SEID, urrID)

						// WNC: Call HandleEventReport with RS event ID
						smContext.HandleEventReport(smf_context.EventIDRouterSolicitation)
					} else {
						logger.PfcpLog.Debugf("WNC: Eveth trigger for non-RS URR %d (RS_MONITOR_URR=%d)", urrID, rsMonitorUrrId)
					}
				}
			}
		}
	}

	// TS 23.502 4.2.3.3 2b. Send Data Notification Ack, SMF->UPF
	cause.CauseValue = pfcpType.CauseRequestAccepted
	pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, seqFromUPF, remoteSEID)
}
