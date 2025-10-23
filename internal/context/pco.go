// ProtocolConfigurationOptions
package context

type ProtocolConfigurationOptions struct {
	DNSIPv4Request     bool
	DNSIPv6Request     bool
	PCSCFIPv4Request   bool
	PCSCFIPv6Request   bool // WNC: IPv6 PCSCF support (Phase 2.4)
	IPv4LinkMTURequest bool
}
