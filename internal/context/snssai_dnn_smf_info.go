package context

import "net"

// SnssaiSmfInfo records the SMF S-NSSAI related information
type SnssaiSmfInfo struct {
	Snssai   SNssai
	DnnInfos map[string]*SnssaiSmfDnnInfo
}

// SnssaiSmfDnnInfo records the SMF per S-NSSAI DNN information
type SnssaiSmfDnnInfo struct {
	DNS                       DNS
	PCSCF                     PCSCF
	RouterSolicitationMonitor bool   // WNC: Enable Router Solicitation monitoring for this DNN (default: false)
	DefaultUlFlow             string // WNC: Default uplink flow description (e.g., "permit out ip from assigned to any")
	DefaultDlFlow             string // WNC: Default downlink flow description (e.g., "permit out ip from any to assigned")
}

type DNS struct {
	IPv4Addr net.IP
	IPv6Addr net.IP
}

type PCSCF struct {
	IPv4Addr net.IP
}
