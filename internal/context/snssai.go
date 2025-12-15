package context

import (
	"net"
	"strings"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/smf/pkg/factory"
)

type SNssai struct {
	Sst int32
	Sd  string
}

// Equal return true if two S-NSSAI is equal
func (s *SNssai) Equal(target *SNssai) bool {
	return s.Sst == target.Sst && strings.EqualFold(s.Sd, target.Sd)
}

func (s *SNssai) EqualModelsSnssai(target *models.Snssai) bool {
	return s.Sst == target.Sst && strings.EqualFold(s.Sd, target.Sd)
}

type SnssaiUPFInfo struct {
	SNssai  *SNssai
	DnnList []*DnnUPFInfoItem
}

// DnnUpfInfoItem presents UPF dnn information
type DnnUPFInfoItem struct {
	Dnn             string
	DnaiList        []string
	PduSessionTypes *models.PduSessionTypes
	UeIPPools       []*UeIPPool // IPv4 dynamic pools
	StaticIPPools   []*UeIPPool // IPv4 static pools
	UeIPv6Pools     []*UeIPPool // IPv6 dynamic pools
	StaticIPv6Pools []*UeIPPool // IPv6 static pools
	// WNC: Store full static assignment config for round-trip fidelity
	IPv6StaticAssignments     []*factory.StaticUEIPv6Assignment // Full IPv6 static assignment config
	RouterSolicitationMonitor bool                               // WNC: Enable RS monitoring for this DNN (default: false)
	DefaultUlFlow             string                             // WNC: Default uplink flow description
	DefaultDlFlow             string                             // WNC: Default downlink flow description
}

// ContainsDNAI return true if the this dnn Info contains the specify DNAI
func (d *DnnUPFInfoItem) ContainsDNAI(targetDnai string) bool {
	if targetDnai == "" {
		return d.DnaiList == nil || len(d.DnaiList) == 0
	}
	for _, dnai := range d.DnaiList {
		if dnai == targetDnai {
			return true
		}
	}
	return false
}

// ContainsIPPool returns true if the ip pool of this upf dnn info contains the `ip`
func (d *DnnUPFInfoItem) ContainsIPPool(ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, ipPool := range d.UeIPPools {
		if ipPool.ueSubNet.Contains(ip) {
			return true
		}
	}
	return false
}
