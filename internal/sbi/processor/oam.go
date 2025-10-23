package processor

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/logger"
	"github.com/free5gc/smf/pkg/factory"
)

type PDUSessionInfo struct {
	Supi         string
	PDUSessionID string
	Dnn          string
	Sst          string
	Sd           string
	AnType       models.AccessType
	PDUAddress   string // WNC: Legacy field for backward compatibility, may be empty for IPv6-only sessions
	PDUAddressIPv4 string // WNC: IPv4 address for IPv4 and dual-stack sessions
	PDUAddressIPv6 string // WNC: IPv6 address for IPv6 and dual-stack sessions
	SessionRule  models.SessionRule
	UpCnxState   models.UpCnxState
	Tunnel       context.UPTunnel
}

func (p *Processor) HandleOAMGetUEPDUSessionInfo(c *gin.Context, smContextRef string) {
	smContext := context.GetSMContextByRef(smContextRef)
	if smContext == nil {
		c.JSON(http.StatusNotFound, nil)
		return
	}

	pduSessionInfo := &PDUSessionInfo{
		Supi:         smContext.Supi,
		PDUSessionID: strconv.Itoa(int(smContext.PDUSessionID)),
		Dnn:          smContext.Dnn,
		Sst:          strconv.Itoa(int(smContext.SNssai.Sst)),
		Sd:           smContext.SNssai.Sd,
		AnType:       smContext.AnType,
		UpCnxState:   smContext.UpCnxState,
		// Tunnel: context.UPTunnel{
		// 	//UpfRoot:  smContext.Tunnel.UpfRoot,
		// 	ULCLRoot: smContext.Tunnel.UpfRoot,
		// },
	}

	// WNC: Populate address fields based on session type
	// Support both legacy PDUAddress and new per-family fields for IPv6 visibility
	if smContext.PDUAddressIPv4 != nil {
		pduSessionInfo.PDUAddressIPv4 = smContext.PDUAddressIPv4.String()
		// Legacy field for backward compatibility
		pduSessionInfo.PDUAddress = smContext.PDUAddressIPv4.String()
	}

	if smContext.PDUAddressIPv6 != nil {
		pduSessionInfo.PDUAddressIPv6 = smContext.PDUAddressIPv6.String()
		// For IPv6-only sessions, also populate legacy field
		if smContext.PDUAddressIPv4 == nil {
			pduSessionInfo.PDUAddress = smContext.PDUAddressIPv6.String()
		}
	}

	// Fallback to legacy PDUAddress for backward compatibility with older sessions
	if smContext.PDUAddress != nil && pduSessionInfo.PDUAddress == "" {
		pduSessionInfo.PDUAddress = smContext.PDUAddress.String()
		// Try to determine if it's IPv4 or IPv6
		if smContext.PDUAddress.To4() != nil {
			pduSessionInfo.PDUAddressIPv4 = smContext.PDUAddress.String()
		} else {
			pduSessionInfo.PDUAddressIPv6 = smContext.PDUAddress.String()
		}
	}

	if pduSessionInfo.PDUAddress == "" && pduSessionInfo.PDUAddressIPv4 == "" && pduSessionInfo.PDUAddressIPv6 == "" {
		logger.PduSessLog.Infof("WNC: OAM query for session without PDU address (non-IP session type 0x%02x)",
			smContext.SelectedPDUSessionType)
	}

	c.JSON(http.StatusOK, pduSessionInfo)
}

func (p *Processor) HandleGetSMFUserPlaneInfo(c *gin.Context) {
	c.JSON(http.StatusOK, factory.SmfConfig.Configuration.UserPlaneInformation)
}
