package processor

import (
	"context"
	"fmt"
	"time"

	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp"
	"github.com/free5gc/pfcp/pfcpType"
	smf_context "github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/logger"
	"github.com/free5gc/smf/internal/pfcp/message"
)

func (p *Processor) ToBeAssociatedWithUPF(smfPfcpContext context.Context, upf *smf_context.UPF) {
	var upfStr string
	if upf.NodeID.NodeIdType == pfcpType.NodeIdTypeFqdn {
		upfStr = fmt.Sprintf("[%s](%s)", upf.NodeID.FQDN, upf.NodeID.ResolveNodeIdToIp().String())
	} else {
		upfStr = fmt.Sprintf("[%s]", upf.NodeID.ResolveNodeIdToIp().String())
	}

	for {
		// check if SMF PFCP context (parent) was canceled
		// note: UPF AssociationContexts are children of smfPfcpContext
		select {
		case <-smfPfcpContext.Done():
			logger.MainLog.Infoln("Canceled SMF PFCP context")
			return
		default:
			ensureSetupPfcpAssociation(smfPfcpContext, upf, upfStr)
			if smf_context.GetSelf().PfcpHeartbeatInterval == 0 {
				return
			}
			keepHeartbeatTo(upf, upfStr)
			// returns when UPF heartbeat loss is detected or association is canceled

			p.releaseAllResourcesOfUPF(upf, upfStr)
		}
	}
}

func (p *Processor) ReleaseAllResourcesOfUPF(upf *smf_context.UPF) {
	var upfStr string
	if upf.NodeID.NodeIdType == pfcpType.NodeIdTypeFqdn {
		upfStr = fmt.Sprintf("[%s](%s)", upf.NodeID.FQDN, upf.NodeID.ResolveNodeIdToIp().String())
	} else {
		upfStr = fmt.Sprintf("[%s]", upf.NodeID.ResolveNodeIdToIp().String())
	}
	p.releaseAllResourcesOfUPF(upf, upfStr)
}

func ensureSetupPfcpAssociation(parentContext context.Context, upf *smf_context.UPF, upfStr string) {
	alertTime := time.Now()
	alertInterval := smf_context.GetSelf().AssocFailAlertInterval
	retryInterval := smf_context.GetSelf().AssocFailRetryInterval
	for {
		err := setupPfcpAssociation(upf, upfStr)
		if err == nil {
			// success
			// assign UPF an AssociationContext, with SMF PFCP Context as parent
			upf.AssociationContext, upf.CancelAssociation = context.WithCancel(parentContext)
			return
		}
		logger.MainLog.Warnf("Failed to setup an association with UPF[%s], error:%+v", upfStr, err)
		now := time.Now()
		logger.MainLog.Debugf("now %+v, alertTime %+v", now, alertTime)
		if now.After(alertTime.Add(alertInterval)) {
			logger.MainLog.Errorf("ALERT for UPF[%s]", upfStr)
			alertTime = now
		}
		logger.MainLog.Debugf("Wait %+v until next retry attempt", retryInterval)
		timer := time.After(retryInterval)
		select { // no default case, either case needs to be true to continue
		case <-parentContext.Done():
			logger.MainLog.Infoln("Canceled SMF PFCP context")
			return
		case <-timer:
			continue
		}
	}
}

func setupPfcpAssociation(upf *smf_context.UPF, upfStr string) error {
	logger.MainLog.Infof("Sending PFCP Association Request to UPF%s", upfStr)

	resMsg, err := message.SendPfcpAssociationSetupRequest(upf.NodeID)
	if err != nil {
		return err
	}

	rsp := resMsg.PfcpMessage.Body.(pfcp.PFCPAssociationSetupResponse)

	if rsp.Cause == nil || rsp.Cause.CauseValue != pfcpType.CauseRequestAccepted {
		return fmt.Errorf("received PFCP Association Setup Not Accepted Response from UPF%s", upfStr)
	}

	nodeID := rsp.NodeID
	if nodeID == nil {
		return fmt.Errorf("pfcp association needs NodeID")
	}

	// WNC: Extract IPv6 capability from UPF Function Features in response
	// This mirrors the logic in HandlePfcpAssociationSetupRequest for the request path
	// Bit 0 of SupportedFeatures indicates IPv6 support in gtp5g (3GPP TS 29.244)
	if rsp.UPFunctionFeatures != nil {
		upf.SupportsIPv6 = (rsp.UPFunctionFeatures.SupportedFeatures & 0x01) != 0
		logger.MainLog.Infof("WNC: UPF[%s] IPv6 support: %v (features: 0x%x)",
			upf.NodeID.ResolveNodeIdToIp().String(), upf.SupportsIPv6,
			rsp.UPFunctionFeatures.SupportedFeatures)
	} else {
		// WNC: Default to false if no UPF Function Features provided
		upf.SupportsIPv6 = false
		logger.MainLog.Warnf("WNC: UPF[%s] did not provide UPF Function Features in response, assuming no IPv6 support",
			upf.NodeID.ResolveNodeIdToIp().String())
	}

	// WNC: CRITICAL - Parse UserPlaneIPResourceInformation from PFCP Association Setup Response
	// The UPF should advertise its N3/N9 interface addresses here (both request and response can contain this)
	if rsp.UserPlaneIPResourceInformation != nil {
		upIpResInfo := rsp.UserPlaneIPResourceInformation

		logger.MainLog.Infof("WNC: UPF[%s] RESPONSE advertised UserPlaneIPResourceInformation - V4: %v, V6: %v, "+
			"IPv4: %v, IPv6: %v, NetworkInstance: %s, SourceInterface: %d",
			upf.NodeID.ResolveNodeIdToIp().String(),
			upIpResInfo.V4, upIpResInfo.V6,
			upIpResInfo.Ipv4Address, upIpResInfo.Ipv6Address,
			upIpResInfo.NetworkInstance.NetworkInstance, upIpResInfo.SourceInterface)

		// WNC: Log what we received for dual-stack troubleshooting
		if upIpResInfo.V4 && upIpResInfo.Ipv4Address != nil {
			logger.MainLog.Infof("WNC: UPF[%s] PFCP RESPONSE advertised IPv4 address: %s",
				upf.NodeID.ResolveNodeIdToIp().String(), upIpResInfo.Ipv4Address.String())
		} else {
			logger.MainLog.Warnf("WNC: UPF[%s] PFCP RESPONSE did NOT advertise IPv4 address (V4 flag: %v)",
				upf.NodeID.ResolveNodeIdToIp().String(), upIpResInfo.V4)
		}

		if upIpResInfo.V6 && upIpResInfo.Ipv6Address != nil {
			logger.MainLog.Infof("WNC: UPF[%s] PFCP RESPONSE advertised IPv6 address: %s",
				upf.NodeID.ResolveNodeIdToIp().String(), upIpResInfo.Ipv6Address.String())
		} else {
			logger.MainLog.Warnf("WNC: UPF[%s] PFCP RESPONSE did NOT advertise IPv6 address (V6 flag: %v) - "+
				"This is the root cause of IPv6EndPointAddresses being 0!",
				upf.NodeID.ResolveNodeIdToIp().String(), upIpResInfo.V6)
		}

		// WNC: TODO - Update UPF interface information from PFCP response
		// For now, we log the discrepancy so operators can see if PFCP differs from YAML config
		logger.MainLog.Infof("WNC: UPF[%s] PFCP RESPONSE vs Config - "+
			"Current N3 interfaces in SMF context: %d, Current N9 interfaces: %d",
			upf.NodeID.ResolveNodeIdToIp().String(), len(upf.N3Interfaces), len(upf.N9Interfaces))

	} else {
		logger.MainLog.Warnf("WNC: UPF[%s] did NOT provide UserPlaneIPResourceInformation in PFCP Association Setup RESPONSE! "+
			"SMF will rely entirely on static smfcfg.yaml configuration. "+
			"Check if UPF's PFCP implementation (go-gtp5gnl) is sending interface information in REQUEST instead of RESPONSE.",
			upf.NodeID.ResolveNodeIdToIp().String())
	}

	logger.MainLog.Infof("Received PFCP Association Setup Accepted Response from UPF%s", upfStr)
	logger.MainLog.Infof("UPF(%s) setup association", upf.NodeID.ResolveNodeIdToIp().String())

	return nil
}

func keepHeartbeatTo(upf *smf_context.UPF, upfStr string) {
	for {
		err := doPfcpHeartbeat(upf, upfStr)
		if err != nil {
			logger.MainLog.Errorf("PFCP Heartbeat error: %v", err)
			return
		}

		timer := time.After(smf_context.GetSelf().PfcpHeartbeatInterval)
		select {
		case <-upf.AssociationContext.Done():
			logger.MainLog.Infof("Canceled association to UPF[%s]", upfStr)
			return
		case <-timer:
			continue
		}
	}
}

func doPfcpHeartbeat(upf *smf_context.UPF, upfStr string) error {
	if err := upf.IsAssociated(); err != nil {
		return fmt.Errorf("Cancel heartbeat: %+v", err)
	}

	logger.MainLog.Debugf("Sending PFCP Heartbeat Request to UPF%s", upfStr)

	resMsg, err := message.SendPfcpHeartbeatRequest(upf)
	if err != nil {
		upf.CancelAssociation()
		upf.RecoveryTimeStamp = time.Time{}
		return fmt.Errorf("SendPfcpHeartbeatRequest error: %w", err)
	}

	rsp := resMsg.PfcpMessage.Body.(pfcp.HeartbeatResponse)
	if rsp.RecoveryTimeStamp == nil {
		logger.MainLog.Warnf("Received PFCP Heartbeat Response without timestamp from UPF%s", upfStr)
		return nil
	}

	logger.MainLog.Debugf("Received PFCP Heartbeat Response from UPF%s", upfStr)
	if upf.RecoveryTimeStamp.IsZero() {
		// first receive
		upf.RecoveryTimeStamp = rsp.RecoveryTimeStamp.RecoveryTimeStamp
	} else if upf.RecoveryTimeStamp.Before(rsp.RecoveryTimeStamp.RecoveryTimeStamp) {
		// received a newer recovery timestamp
		upf.CancelAssociation()
		upf.RecoveryTimeStamp = time.Time{}
		return fmt.Errorf("received PFCP Heartbeat Response RecoveryTimeStamp has been updated")
	}
	return nil
}

func (p *Processor) releaseAllResourcesOfUPF(upf *smf_context.UPF, upfStr string) {
	logger.MainLog.Infof("Release all resources of UPF %s", upfStr)

	upf.ProcEachSMContext(func(smContext *smf_context.SMContext) {
		smContext.SMLock.Lock()
		defer smContext.SMLock.Unlock()
		switch smContext.State() {
		case smf_context.Active, smf_context.ModificationPending, smf_context.PFCPModification:
			needToSendNotify, removeContext := p.requestAMFToReleasePDUResources(smContext)
			if needToSendNotify {
				p.SendReleaseNotification(smContext)
			}
			if removeContext {
				// Notification has already been sent, if it is needed
				p.RemoveSMContextFromAllNF(smContext, false)
			}
		}
	})
}

func (p *Processor) requestAMFToReleasePDUResources(
	smContext *smf_context.SMContext,
) (sendNotify bool, releaseContext bool) {
	n1n2Request := models.N1N2MessageTransferRequest{}
	// TS 23.502 4.3.4.2 3b. Send Namf_Communication_N1N2MessageTransfer Request, SMF->AMF
	n1n2Request.JsonData = &models.N1N2MessageTransferReqData{
		PduSessionId: smContext.PDUSessionID,
		SkipInd:      true,
	}
	cause := nasMessage.Cause5GSMNetworkFailure
	if buf, err := smf_context.BuildGSMPDUSessionReleaseCommand(smContext, cause, false); err != nil {
		logger.MainLog.Errorf("Build GSM PDUSessionReleaseCommand failed: %+v", err)
	} else {
		n1n2Request.BinaryDataN1Message = buf
		n1n2Request.JsonData.N1MessageContainer = &models.N1MessageContainer{
			N1MessageClass:   "SM",
			N1MessageContent: &models.RefToBinaryData{ContentId: "GSM_NAS"},
		}
	}
	if smContext.UpCnxState != models.UpCnxState_DEACTIVATED {
		if buf, err := smf_context.BuildPDUSessionResourceReleaseCommandTransfer(smContext); err != nil {
			logger.MainLog.Errorf("Build PDUSessionResourceReleaseCommandTransfer failed: %+v", err)
		} else {
			n1n2Request.BinaryDataN2Information = buf
			n1n2Request.JsonData.N2InfoContainer = &models.N2InfoContainer{
				N2InformationClass: models.N2InformationClass_SM,
				SmInfo: &models.N2SmInformation{
					PduSessionId: smContext.PDUSessionID,
					N2InfoContent: &models.N2InfoContent{
						NgapIeType: models.AmfCommunicationNgapIeType_PDU_RES_REL_CMD,
						NgapData: &models.RefToBinaryData{
							ContentId: "N2SmInformation",
						},
					},
					SNssai: smContext.SNssai,
				},
			}
		}
	}

	ctx, _, errToken := smf_context.GetSelf().GetTokenCtx(models.ServiceName_NAMF_COMM, models.NrfNfManagementNfType_AMF)
	if errToken != nil {
		return false, false
	}

	rspData, err := p.Consumer().
		N1N2MessageTransfer(ctx, smContext.Supi, n1n2Request, smContext.CommunicationClientApiPrefix)

	if err != nil || rspData == nil {
		logger.ConsumerLog.Warnf("N1N2MessageTransfer for RequestAMFToReleasePDUResources failed: %+v", err)
		// keep SM Context to avoid inconsistency with AMF
		smContext.SetState(smf_context.InActive)
	} else {
		if rspData.Cause == models.N1N2MessageTransferCause_N1_MSG_NOT_TRANSFERRED {
			// the PDU Session Release Command was not transferred to the UE since it is in CM-IDLE state.
			//   ref. step3b of "4.3.4.2 UE or network requested PDU Session Release for Non-Roaming and
			//        Roaming with Local Breakout" in TS23.502
			// it is needed to remove both AMF's and SMF's SM Contexts immediately
			smContext.SetState(smf_context.InActive)
			return true, true
		} else if rspData.Cause == models.N1N2MessageTransferCause_N1_N2_TRANSFER_INITIATED {
			// wait for N2 PDU Session Release Response
			smContext.SetState(smf_context.InActivePending)
		} else {
			// other causes are unexpected.
			// keep SM Context to avoid inconsistency with AMF
			smContext.SetState(smf_context.InActive)
		}
	}
	return false, false
}
