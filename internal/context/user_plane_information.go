package context

import (
	"errors"
	"math/rand"
	"net"
	"reflect"
	"sort"
	"sync"

	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/smf/internal/logger"
	"github.com/free5gc/smf/pkg/factory"
)

// UserPlaneInformation store userplane topology
type UserPlaneInformation struct {
	Mu                        sync.RWMutex // protect UPF and topology structure
	UPNodes                   map[string]*UPNode
	UPFs                      map[string]*UPNode
	AccessNetwork             map[string]*UPNode
	UPFIPToName               map[string]string
	UPFsID                    map[string]string               // name to id
	UPFsIPtoID                map[string]string               // ip->id table, for speed optimization
	DefaultUserPlanePath      map[string][]*UPNode            // DNN to Default Path
	DefaultUserPlanePathToUPF map[string]map[string][]*UPNode // DNN and UPF to Default Path
}

type UPNodeType string

const (
	UPNODE_UPF UPNodeType = "UPF"
	UPNODE_AN  UPNodeType = "AN"
)

// UPNode represent the user plane node topology
type UPNode struct {
	Name   string
	Type   UPNodeType
	NodeID pfcpType.NodeID
	ANIP   net.IP
	Dnn    string
	Links  []*UPNode
	UPF    *UPF
}

func (u *UPNode) MatchedSelection(selection *UPFSelectionParams) bool {
	for _, snssaiInfo := range u.UPF.SNssaiInfos {
		currentSnssai := snssaiInfo.SNssai
		if currentSnssai.Equal(selection.SNssai) {
			for _, dnnInfo := range snssaiInfo.DnnList {
				if dnnInfo.Dnn == selection.Dnn {
					if selection.Dnai == "" {
						return true
					} else if dnnInfo.ContainsDNAI(selection.Dnai) {
						return true
					}
				}
			}
		}
	}
	return false
}

// UPPath represent User Plane Sequence of this path
type UPPath []*UPNode

func AllocateUPFID() {
	UPFsID := smfContext.UserPlaneInformation.UPFsID
	UPFsIPtoID := smfContext.UserPlaneInformation.UPFsIPtoID

	for upfName, upfNode := range smfContext.UserPlaneInformation.UPFs {
		upfid := upfNode.UPF.UUID()
		upfip := upfNode.NodeID.ResolveNodeIdToIp().String()

		UPFsID[upfName] = upfid
		UPFsIPtoID[upfip] = upfid
	}
}

// NewUserPlaneInformation process the configuration then returns a new instance of UserPlaneInformation
func NewUserPlaneInformation(upTopology *factory.UserPlaneInformation) *UserPlaneInformation {
	nodePool := make(map[string]*UPNode)
	upfPool := make(map[string]*UPNode)
	anPool := make(map[string]*UPNode)
	upfIPMap := make(map[string]string)
	allUEIPPools := []*UeIPPool{}

	for name, node := range upTopology.UPNodes {
		upNode := new(UPNode)
		upNode.Name = name
		upNode.Type = UPNodeType(node.Type)
		switch upNode.Type {
		case UPNODE_AN:
			upNode.ANIP = net.ParseIP(node.ANIP)
			anPool[name] = upNode
		case UPNODE_UPF:
			// ParseIp() always return 16 bytes
			// so we can't use the length of return ip to separate IPv4 and IPv6
			// This is just a work around
			var ip net.IP
			if net.ParseIP(node.NodeID).To4() == nil {
				ip = net.ParseIP(node.NodeID)
			} else {
				ip = net.ParseIP(node.NodeID).To4()
			}

			switch len(ip) {
			case net.IPv4len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType: pfcpType.NodeIdTypeIpv4Address,
					IP:         ip,
				}
			case net.IPv6len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType: pfcpType.NodeIdTypeIpv6Address,
					IP:         ip,
				}
			default:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType: pfcpType.NodeIdTypeFqdn,
					FQDN:       node.NodeID,
				}
			}

			upNode.UPF = NewUPF(&upNode.NodeID, node.InterfaceUpfInfoList)
			upNode.UPF.Addr = node.Addr
			snssaiInfos := make([]*SnssaiUPFInfo, 0)
			for _, snssaiInfoConfig := range node.SNssaiInfos {
				snssaiInfo := SnssaiUPFInfo{
					SNssai: &SNssai{
						Sst: snssaiInfoConfig.SNssai.Sst,
						Sd:  snssaiInfoConfig.SNssai.Sd,
					},
					DnnList: make([]*DnnUPFInfoItem, 0),
				}

				for _, dnnInfoConfig := range snssaiInfoConfig.DnnUpfInfoList {
					ueIPPools := make([]*UeIPPool, 0)
					staticUeIPPools := make([]*UeIPPool, 0)
					for _, pool := range dnnInfoConfig.Pools {
						ueIPPool := NewUEIPPool(pool)
						if ueIPPool == nil {
							logger.InitLog.Fatalf("invalid pools value: %+v", pool)
						} else {
							ueIPPools = append(ueIPPools, ueIPPool)
							allUEIPPools = append(allUEIPPools, ueIPPool)
						}
					}
					for _, staticPool := range dnnInfoConfig.StaticPools {
						staticUeIPPool := NewUEIPPool(staticPool)
						if staticUeIPPool == nil {
							logger.InitLog.Fatalf("invalid pools value: %+v", staticPool)
						} else {
							staticUeIPPools = append(staticUeIPPools, staticUeIPPool)
							for _, dynamicUePool := range ueIPPools {
								if dynamicUePool.ueSubNet.Contains(staticUeIPPool.ueSubNet.IP) {
									if err := dynamicUePool.Exclude(staticUeIPPool); err != nil {
										logger.InitLog.Fatalf("exclude static Pool[%s] failed: %v",
											staticUeIPPool.ueSubNet, err)
									}
								}
							}
						}
					}

					// WNC: Process IPv6 pools
					ipv6Pools := make([]*UeIPPool, 0)
					ipv6StaticPools := make([]*UeIPPool, 0)
					for _, pool := range dnnInfoConfig.UeIPv6Pools {
						ipv6Pool := NewUEIPv6Pool(pool)
						if ipv6Pool == nil {
							logger.InitLog.Fatalf("WNC: invalid IPv6 pool value: %+v", pool)
						} else {
							ipv6Pools = append(ipv6Pools, ipv6Pool)
							allUEIPPools = append(allUEIPPools, ipv6Pool)
							logger.InitLog.Infof("WNC: Loaded IPv6 pool for DNN %s: %s",
								dnnInfoConfig.Dnn, pool.Prefix)
						}
					}
					for _, staticPool := range dnnInfoConfig.StaticIPv6Pools {
						ipv6StaticPool := NewUEIPv6Pool(staticPool)
						if ipv6StaticPool == nil {
							logger.InitLog.Fatalf("WNC: invalid IPv6 static pool value: %+v", staticPool)
						} else {
							ipv6StaticPools = append(ipv6StaticPools, ipv6StaticPool)
							logger.InitLog.Infof("WNC: Loaded IPv6 static pool for DNN %s: %s",
								dnnInfoConfig.Dnn, staticPool.Prefix)
						}
					}

					// WNC: Process IPv6 static assignments - preserve full factory config
					ipv6StaticAssignments := make([]*factory.StaticUEIPv6Assignment, 0)
					for _, assignment := range dnnInfoConfig.IPv6StaticAssignments {
						ip := net.ParseIP(assignment.Address)
						if ip == nil {
							logger.InitLog.Fatalf("WNC: invalid IPv6 static assignment address: %s",
								assignment.Address)
						}
						// Store the full assignment config for round-trip fidelity
						ipv6StaticAssignments = append(ipv6StaticAssignments, assignment)
						logger.InitLog.Infof("WNC: Loaded IPv6 static assignment for SUPI %s: %s/%d",
							assignment.Supi, assignment.Address, assignment.PrefixLength)
					}

					for _, pool := range ueIPPools {
						if pool.pool.Min() != pool.pool.Max() {
							if err := pool.pool.Reserve(pool.pool.Min(), pool.pool.Min()); err != nil {
								logger.InitLog.Errorf("Remove network address failed for %s: %s", pool.ueSubNet.String(), err)
							}
							if err := pool.pool.Reserve(pool.pool.Max(), pool.pool.Max()); err != nil {
								logger.InitLog.Errorf("Remove network address failed for %s: %s", pool.ueSubNet.String(), err)
							}
						}
						logger.InitLog.Debugf("%d-%s %s %s",
							snssaiInfo.SNssai.Sst, snssaiInfo.SNssai.Sd,
							dnnInfoConfig.Dnn, pool.dump())
					}
					snssaiInfo.DnnList = append(snssaiInfo.DnnList, &DnnUPFInfoItem{
						Dnn:                       dnnInfoConfig.Dnn,
						DnaiList:                  dnnInfoConfig.DnaiList,
						PduSessionTypes:           dnnInfoConfig.PduSessionTypes,
						UeIPPools:                 ueIPPools,
						StaticIPPools:             staticUeIPPools,
						UeIPv6Pools:               ipv6Pools,
						StaticIPv6Pools:           ipv6StaticPools,
						IPv6StaticAssignments:     ipv6StaticAssignments,
						RouterSolicitationMonitor: dnnInfoConfig.RouterSolicitationMonitor, // WNC: Propagate RS monitor flag from config
						DefaultUlFlow:             dnnInfoConfig.DefaultUlFlow,             // WNC: Propagate default UL flow from config
						DefaultDlFlow:             dnnInfoConfig.DefaultDlFlow,             // WNC: Propagate default DL flow from config
					})
				}
				snssaiInfos = append(snssaiInfos, &snssaiInfo)
			}
			upNode.UPF.SNssaiInfos = snssaiInfos
			upfPool[name] = upNode
		default:
			logger.InitLog.Warningf("invalid UPNodeType: %s\n", upNode.Type)
		}

		nodePool[name] = upNode

		ipStr := upNode.NodeID.ResolveNodeIdToIp().String()
		upfIPMap[ipStr] = name
	}

	if isOverlap(allUEIPPools) {
		logger.InitLog.Fatalf("overlap cidr value between UPFs")
	} else {
		logger.InitLog.Infof("WNC: Validated %d UE IP pools (IPv4/IPv6) - no overlaps detected", len(allUEIPPools))
	}

	for _, link := range upTopology.Links {
		nodeA := nodePool[link.A]
		nodeB := nodePool[link.B]
		if nodeA == nil || nodeB == nil {
			logger.InitLog.Warningf("One of link edges does not exist. UPLink [%s] <=> [%s] not establish\n", link.A, link.B)
			continue
		}
		if nodeInLink(nodeB, nodeA.Links) != -1 || nodeInLink(nodeA, nodeB.Links) != -1 {
			logger.InitLog.Warningf("One of link edges already exist. UPLink [%s] <=> [%s] not establish\n", link.A, link.B)
			continue
		}
		nodeA.Links = append(nodeA.Links, nodeB)
		nodeB.Links = append(nodeB.Links, nodeA)
	}

	userplaneInformation := &UserPlaneInformation{
		UPNodes:                   nodePool,
		UPFs:                      upfPool,
		AccessNetwork:             anPool,
		UPFIPToName:               upfIPMap,
		UPFsID:                    make(map[string]string),
		UPFsIPtoID:                make(map[string]string),
		DefaultUserPlanePath:      make(map[string][]*UPNode),
		DefaultUserPlanePathToUPF: make(map[string]map[string][]*UPNode),
	}

	return userplaneInformation
}

func (upi *UserPlaneInformation) UpNodesToConfiguration() map[string]*factory.UPNode {
	nodes := make(map[string]*factory.UPNode)
	for name, upNode := range upi.UPNodes {
		u := new(factory.UPNode)
		switch upNode.Type {
		case UPNODE_UPF:
			u.Type = "UPF"
		case UPNODE_AN:
			u.Type = "AN"
			u.ANIP = upNode.ANIP.String()
		default:
			u.Type = "Unknown"
		}
		nodeIDtoIp := upNode.NodeID.ResolveNodeIdToIp()
		if nodeIDtoIp != nil {
			u.NodeID = nodeIDtoIp.String()
		}
		if upNode.UPF != nil {
			if upNode.UPF.SNssaiInfos != nil {
				FsNssaiInfoList := make([]*factory.SnssaiUpfInfoItem, 0)
				for _, sNssaiInfo := range upNode.UPF.SNssaiInfos {
					FDnnUpfInfoList := make([]*factory.DnnUpfInfoItem, 0)
					for _, dnnInfo := range sNssaiInfo.DnnList {
						FUEIPPools := make([]*factory.UEIPPool, 0)
						FStaticUEIPPools := make([]*factory.UEIPPool, 0)
						for _, pool := range dnnInfo.UeIPPools {
							// Use stored factory config if available, otherwise construct from subnet
							if pool.factoryIPv4Pool != nil {
								FUEIPPools = append(FUEIPPools, pool.factoryIPv4Pool)
							} else {
								FUEIPPools = append(FUEIPPools, &factory.UEIPPool{
									Cidr: pool.ueSubNet.String(),
								})
							}
						} // for pool
						for _, pool := range dnnInfo.StaticIPPools {
							// Use stored factory config if available, otherwise construct from subnet
							if pool.factoryIPv4Pool != nil {
								FStaticUEIPPools = append(FStaticUEIPPools, pool.factoryIPv4Pool)
							} else {
								FStaticUEIPPools = append(FStaticUEIPPools, &factory.UEIPPool{
									Cidr: pool.ueSubNet.String(),
								})
							}
						} // for static pool

						// WNC: Export IPv6 pools with full factory configuration
						FUeIPv6Pools := make([]*factory.UEIPv6Pool, 0)
						FStaticIPv6Pools := make([]*factory.UEIPv6Pool, 0)
						for _, pool := range dnnInfo.UeIPv6Pools {
							// Use stored factory config for full round-trip fidelity
							if pool.factoryIPv6Pool != nil {
								FUeIPv6Pools = append(FUeIPv6Pools, pool.factoryIPv6Pool)
							}
						} // for IPv6 pool
						for _, pool := range dnnInfo.StaticIPv6Pools {
							// Use stored factory config for full round-trip fidelity
							if pool.factoryIPv6Pool != nil {
								FStaticIPv6Pools = append(FStaticIPv6Pools, pool.factoryIPv6Pool)
							}
						} // for IPv6 static pool

						// WNC: Export IPv6 static assignments - already in factory format
						FIPv6StaticAssignments := dnnInfo.IPv6StaticAssignments

						FDnnUpfInfoList = append(FDnnUpfInfoList, &factory.DnnUpfInfoItem{
							Dnn:                   dnnInfo.Dnn,
							DnaiList:              dnnInfo.DnaiList,
							PduSessionTypes:       dnnInfo.PduSessionTypes,
							Pools:                 FUEIPPools,
							StaticPools:           FStaticUEIPPools,
							UeIPv6Pools:           FUeIPv6Pools,
							StaticIPv6Pools:       FStaticIPv6Pools,
							IPv6StaticAssignments: FIPv6StaticAssignments,
						})
					} // for dnnInfo
					Fsnssai := &factory.SnssaiUpfInfoItem{
						SNssai: &models.Snssai{
							Sst: sNssaiInfo.SNssai.Sst,
							Sd:  sNssaiInfo.SNssai.Sd,
						},
						DnnUpfInfoList: FDnnUpfInfoList,
					}
					FsNssaiInfoList = append(FsNssaiInfoList, Fsnssai)
				} // for sNssaiInfo
				u.SNssaiInfos = FsNssaiInfoList
			} // if UPF.SNssaiInfos
			FNxList := make([]*factory.InterfaceUpfInfoItem, 0)
			for _, iface := range upNode.UPF.N3Interfaces {
				endpoints := make([]string, 0)
				// upf.go L90
				if iface.EndpointFQDN != "" {
					endpoints = append(endpoints, iface.EndpointFQDN)
				}
				for _, eIP := range iface.IPv4EndPointAddresses {
					endpoints = append(endpoints, eIP.String())
				}
				FNxList = append(FNxList, &factory.InterfaceUpfInfoItem{
					InterfaceType:    models.UpInterfaceType_N3,
					Endpoints:        endpoints,
					NetworkInstances: iface.NetworkInstances,
				})
			} // for N3Interfaces

			for _, iface := range upNode.UPF.N9Interfaces {
				endpoints := make([]string, 0)
				// upf.go L90
				if iface.EndpointFQDN != "" {
					endpoints = append(endpoints, iface.EndpointFQDN)
				}
				for _, eIP := range iface.IPv4EndPointAddresses {
					endpoints = append(endpoints, eIP.String())
				}
				FNxList = append(FNxList, &factory.InterfaceUpfInfoItem{
					InterfaceType:    models.UpInterfaceType_N9,
					Endpoints:        endpoints,
					NetworkInstances: iface.NetworkInstances,
				})
			} // N9Interfaces
			u.InterfaceUpfInfoList = FNxList
		}
		nodes[name] = u
	}

	return nodes
}

func (upi *UserPlaneInformation) LinksToConfiguration() []*factory.UPLink {
	links := make([]*factory.UPLink, 0)
	source, err := upi.selectUPPathSource()
	if err != nil {
		logger.InitLog.Errorf("AN Node not found\n")
	} else {
		visited := make(map[*UPNode]bool)
		queue := make([]*UPNode, 0)
		queue = append(queue, source)
		for {
			node := queue[0]
			queue = queue[1:]
			visited[node] = true
			for _, link := range node.Links {
				if !visited[link] {
					queue = append(queue, link)
					nodeIpStr := node.NodeID.ResolveNodeIdToIp().String()
					ipStr := link.NodeID.ResolveNodeIdToIp().String()
					linkA := upi.UPFIPToName[nodeIpStr]
					linkB := upi.UPFIPToName[ipStr]
					links = append(links, &factory.UPLink{
						A: linkA,
						B: linkB,
					})
				}
			}
			if len(queue) == 0 {
				break
			}
		}
	}
	return links
}

func (upi *UserPlaneInformation) UpNodesFromConfiguration(upTopology *factory.UserPlaneInformation) {
	for name, node := range upTopology.UPNodes {
		if _, ok := upi.UPNodes[name]; ok {
			logger.InitLog.Warningf("Node [%s] already exists in SMF.\n", name)
			continue
		}
		upNode := new(UPNode)
		upNode.Type = UPNodeType(node.Type)
		switch upNode.Type {
		case UPNODE_UPF:
			// ParseIp() always return 16 bytes
			// so we can't use the length of return ip to separate IPv4 and IPv6
			// This is just a work around
			var ip net.IP
			if net.ParseIP(node.NodeID).To4() == nil {
				ip = net.ParseIP(node.NodeID)
			} else {
				ip = net.ParseIP(node.NodeID).To4()
			}

			switch len(ip) {
			case net.IPv4len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType: pfcpType.NodeIdTypeIpv4Address,
					IP:         ip,
				}
			case net.IPv6len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType: pfcpType.NodeIdTypeIpv6Address,
					IP:         ip,
				}
			default:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType: pfcpType.NodeIdTypeFqdn,
					FQDN:       node.NodeID,
				}
			}

			upNode.UPF = NewUPF(&upNode.NodeID, node.InterfaceUpfInfoList)
			snssaiInfos := make([]*SnssaiUPFInfo, 0)
			for _, snssaiInfoConfig := range node.SNssaiInfos {
				snssaiInfo := &SnssaiUPFInfo{
					SNssai: &SNssai{
						Sst: snssaiInfoConfig.SNssai.Sst,
						Sd:  snssaiInfoConfig.SNssai.Sd,
					},
					DnnList: make([]*DnnUPFInfoItem, 0),
				}

				for _, dnnInfoConfig := range snssaiInfoConfig.DnnUpfInfoList {
					ueIPPools := make([]*UeIPPool, 0)
					staticUeIPPools := make([]*UeIPPool, 0)
					for _, pool := range dnnInfoConfig.Pools {
						ueIPPool := NewUEIPPool(pool)
						if ueIPPool == nil {
							logger.InitLog.Fatalf("invalid pools value: %+v", pool)
						} else {
							ueIPPools = append(ueIPPools, ueIPPool)
						}
					}
					for _, pool := range dnnInfoConfig.StaticPools {
						ueIPPool := NewUEIPPool(pool)
						if ueIPPool == nil {
							logger.InitLog.Fatalf("invalid pools value: %+v", pool)
						} else {
							staticUeIPPools = append(staticUeIPPools, ueIPPool)
							for _, dynamicUePool := range ueIPPools {
								if dynamicUePool.ueSubNet.Contains(ueIPPool.ueSubNet.IP) {
									if err := dynamicUePool.Exclude(ueIPPool); err != nil {
										logger.InitLog.Fatalf("exclude static Pool[%s] failed: %v",
											ueIPPool.ueSubNet, err)
									}
								}
							}
						}
					}

					// WNC: Process IPv6 pools (in UpNodesFromConfiguration)
					ipv6Pools := make([]*UeIPPool, 0)
					ipv6StaticPools := make([]*UeIPPool, 0)
					for _, pool := range dnnInfoConfig.UeIPv6Pools {
						ipv6Pool := NewUEIPv6Pool(pool)
						if ipv6Pool == nil {
							logger.InitLog.Fatalf("WNC: invalid IPv6 pool value: %+v", pool)
						} else {
							ipv6Pools = append(ipv6Pools, ipv6Pool)
						}
					}
					for _, staticPool := range dnnInfoConfig.StaticIPv6Pools {
						ipv6StaticPool := NewUEIPv6Pool(staticPool)
						if ipv6StaticPool == nil {
							logger.InitLog.Fatalf("WNC: invalid IPv6 static pool value: %+v", staticPool)
						} else {
							ipv6StaticPools = append(ipv6StaticPools, ipv6StaticPool)
						}
					}

					// WNC: Process IPv6 static assignments - preserve full factory config
					ipv6StaticAssignments := make([]*factory.StaticUEIPv6Assignment, 0)
					for _, assignment := range dnnInfoConfig.IPv6StaticAssignments {
						ip := net.ParseIP(assignment.Address)
						if ip == nil {
							logger.InitLog.Fatalf("WNC: invalid IPv6 static assignment address: %s",
								assignment.Address)
						}
						// Store the full assignment config for round-trip fidelity
						ipv6StaticAssignments = append(ipv6StaticAssignments, assignment)
					}

					snssaiInfo.DnnList = append(snssaiInfo.DnnList, &DnnUPFInfoItem{
						Dnn:                       dnnInfoConfig.Dnn,
						DnaiList:                  dnnInfoConfig.DnaiList,
						PduSessionTypes:           dnnInfoConfig.PduSessionTypes,
						UeIPPools:                 ueIPPools,
						StaticIPPools:             staticUeIPPools,
						UeIPv6Pools:               ipv6Pools,
						StaticIPv6Pools:           ipv6StaticPools,
						IPv6StaticAssignments:     ipv6StaticAssignments,
						RouterSolicitationMonitor: dnnInfoConfig.RouterSolicitationMonitor, // WNC: Propagate RS monitor flag from config
						DefaultUlFlow:             dnnInfoConfig.DefaultUlFlow,             // WNC: Propagate default UL flow from config
						DefaultDlFlow:             dnnInfoConfig.DefaultDlFlow,             // WNC: Propagate default DL flow from config
					})
				}
				snssaiInfos = append(snssaiInfos, snssaiInfo)
			}
			upNode.UPF.SNssaiInfos = snssaiInfos
			upi.UPFs[name] = upNode

			// AllocateUPFID
			upfid := upNode.UPF.UUID()
			upfip := upNode.NodeID.ResolveNodeIdToIp().String()
			upi.UPFsID[name] = upfid
			upi.UPFsIPtoID[upfip] = upfid

		case UPNODE_AN:
			upNode.ANIP = net.ParseIP(node.ANIP)
			upi.AccessNetwork[name] = upNode
		default:
			logger.InitLog.Warningf("invalid UPNodeType: %s\n", upNode.Type)
		}

		upi.UPNodes[name] = upNode

		ipStr := upNode.NodeID.ResolveNodeIdToIp().String()
		upi.UPFIPToName[ipStr] = name
	}

	// overlap UE IP pool validation
	allUEIPPools := []*UeIPPool{}
	for _, upf := range upi.UPFs {
		for _, snssaiInfo := range upf.UPF.SNssaiInfos {
			for _, dnn := range snssaiInfo.DnnList {
				// WNC: Check all pool types (IPv4 and IPv6, dynamic and static)
				allUEIPPools = append(allUEIPPools, dnn.UeIPPools...)
				allUEIPPools = append(allUEIPPools, dnn.StaticIPPools...)
				allUEIPPools = append(allUEIPPools, dnn.UeIPv6Pools...)
				allUEIPPools = append(allUEIPPools, dnn.StaticIPv6Pools...)
			}
		}
	}
	if isOverlap(allUEIPPools) {
		logger.InitLog.Fatalf("overlap cidr value between UPFs")
	} else {
		logger.InitLog.Infof("WNC: Validated %d UE IP pools (IPv4/IPv6) - no overlaps detected", len(allUEIPPools))
	}
}

func (upi *UserPlaneInformation) LinksFromConfiguration(upTopology *factory.UserPlaneInformation) {
	for _, link := range upTopology.Links {
		nodeA := upi.UPNodes[link.A]
		nodeB := upi.UPNodes[link.B]
		if nodeA == nil || nodeB == nil {
			logger.InitLog.Warningf("One of link edges does not exist. UPLink [%s] <=> [%s] not establish\n", link.A, link.B)
			continue
		}
		if nodeInLink(nodeB, nodeA.Links) != -1 || nodeInLink(nodeA, nodeB.Links) != -1 {
			logger.InitLog.Warningf("One of link edges already exist. UPLink [%s] <=> [%s] not establish\n", link.A, link.B)
			continue
		}
		nodeA.Links = append(nodeA.Links, nodeB)
		nodeB.Links = append(nodeB.Links, nodeA)
	}
}

func (upi *UserPlaneInformation) UpNodeDelete(upNodeName string) {
	upNode, ok := upi.UPNodes[upNodeName]
	if ok {
		logger.InitLog.Infof("UPNode [%s] found. Deleting it.\n", upNodeName)
		if upNode.Type == UPNODE_UPF {
			logger.InitLog.Tracef("Delete UPF [%s] from its NodeID.\n", upNodeName)
			RemoveUPFNodeByNodeID(upNode.UPF.NodeID)
			if _, ok = upi.UPFs[upNodeName]; ok {
				logger.InitLog.Tracef("Delete UPF [%s] from upi.UPFs.\n", upNodeName)
				delete(upi.UPFs, upNodeName)
			}
			for selectionStr, destMap := range upi.DefaultUserPlanePathToUPF {
				for destIp, path := range destMap {
					if nodeInPath(upNode, path) != -1 {
						logger.InitLog.Infof("Invalidate cache entry: DefaultUserPlanePathToUPF[%s][%s].\n", selectionStr, destIp)
						delete(upi.DefaultUserPlanePathToUPF[selectionStr], destIp)
					}
				}
			}
		}
		if upNode.Type == UPNODE_AN {
			logger.InitLog.Tracef("Delete AN [%s] from upi.AccessNetwork.\n", upNodeName)
			delete(upi.AccessNetwork, upNodeName)
		}
		logger.InitLog.Tracef("Delete UPNode [%s] from upi.UPNodes.\n", upNodeName)
		delete(upi.UPNodes, upNodeName)

		// update links
		for name, n := range upi.UPNodes {
			if index := nodeInLink(upNode, n.Links); index != -1 {
				logger.InitLog.Infof("Delete UPLink [%s] <=> [%s].\n", name, upNodeName)
				n.Links = removeNodeFromLink(n.Links, index)
			}
		}
	}
}

func nodeInPath(upNode *UPNode, path []*UPNode) int {
	for i, u := range path {
		if u == upNode {
			return i
		}
	}
	return -1
}

func removeNodeFromLink(links []*UPNode, index int) []*UPNode {
	links[index] = links[len(links)-1]
	return links[:len(links)-1]
}

func nodeInLink(upNode *UPNode, links []*UPNode) int {
	for i, n := range links {
		if n == upNode {
			return i
		}
	}
	return -1
}

func (upi *UserPlaneInformation) GetUPFNameByIp(ip string) string {
	return upi.UPFIPToName[ip]
}

func (upi *UserPlaneInformation) GetUPFNodeIDByName(name string) pfcpType.NodeID {
	return upi.UPFs[name].NodeID
}

func (upi *UserPlaneInformation) GetUPFNodeByIP(ip string) *UPNode {
	upfName := upi.GetUPFNameByIp(ip)
	return upi.UPFs[upfName]
}

func (upi *UserPlaneInformation) GetUPFIDByIP(ip string) string {
	return upi.UPFsIPtoID[ip]
}

func (upi *UserPlaneInformation) GetDefaultUserPlanePathByDNN(selection *UPFSelectionParams) (path UPPath) {
	path, pathExist := upi.DefaultUserPlanePath[selection.String()]
	logger.CtxLog.Traceln("In GetDefaultUserPlanePathByDNN")
	logger.CtxLog.Traceln("selection: ", selection.String())
	if pathExist {
		return
	} else {
		pathExist = upi.GenerateDefaultPath(selection)
		if pathExist {
			return upi.DefaultUserPlanePath[selection.String()]
		}
	}
	return nil
}

func (upi *UserPlaneInformation) GetDefaultUserPlanePathByDNNAndUPF(selection *UPFSelectionParams,
	upf *UPNode,
) (path UPPath) {
	nodeID := upf.NodeID.ResolveNodeIdToIp().String()

	if upi.DefaultUserPlanePathToUPF[selection.String()] != nil {
		path, pathExist := upi.DefaultUserPlanePathToUPF[selection.String()][nodeID]
		logger.CtxLog.Traceln("In GetDefaultUserPlanePathByDNNAndUPF")
		logger.CtxLog.Traceln("selection: ", selection.String())
		logger.CtxLog.Traceln("pathExist: ", pathExist)
		if pathExist {
			return path
		}
	}
	if pathExist := upi.GenerateDefaultPathToUPF(selection, upf); pathExist {
		return upi.DefaultUserPlanePathToUPF[selection.String()][nodeID]
	}
	return nil
}

func (upi *UserPlaneInformation) ExistDefaultPath(dnn string) bool {
	_, exist := upi.DefaultUserPlanePath[dnn]
	return exist
}

func GenerateDataPath(upPath UPPath) *DataPath {
	if len(upPath) < 1 {
		logger.CtxLog.Errorf("Invalid data path")
		return nil
	}
	lowerBound := 0
	upperBound := len(upPath) - 1
	var root *DataPathNode
	var node *DataPathNode
	var prevDataPathNode *DataPathNode

	for idx, upNode := range upPath {
		node = NewDataPathNode()
		node.UPF = upNode.UPF

		if idx == lowerBound {
			root = node
			root.AddPrev(nil)
		}
		if idx == upperBound {
			node.AddNext(nil)
		}
		if prevDataPathNode != nil {
			prevDataPathNode.AddNext(node)
			node.AddPrev(prevDataPathNode)
		}
		prevDataPathNode = node
	}

	dataPath := NewDataPath()
	dataPath.FirstDPNode = root
	return dataPath
}

func (upi *UserPlaneInformation) GenerateDefaultPath(selection *UPFSelectionParams) bool {
	var source *UPNode
	var destinations []*UPNode

	for _, node := range upi.AccessNetwork {
		if node.Type == UPNODE_AN {
			source = node
			break
		}
	}

	if source == nil {
		logger.CtxLog.Errorf("There is no AN Node in config file!")
		return false
	}

	destinations = upi.selectMatchUPF(selection)

	if len(destinations) == 0 {
		logger.CtxLog.Errorf("Can't find UPF with DNN[%s] S-NSSAI[sst: %d sd: %s] DNAI[%s]\n", selection.Dnn,
			selection.SNssai.Sst, selection.SNssai.Sd, selection.Dnai)
		return false
	} else {
		logger.CtxLog.Tracef("Find UPF with DNN[%s] S-NSSAI[sst: %d sd: %s] DNAI[%s]\n", selection.Dnn,
			selection.SNssai.Sst, selection.SNssai.Sd, selection.Dnai)
	}

	// Run DFS
	visited := make(map[*UPNode]bool)

	for _, upNode := range upi.UPNodes {
		visited[upNode] = false
	}

	path, pathExist := getPathBetween(source, destinations[0], visited, selection)

	if pathExist {
		if path[0].Type == UPNODE_AN {
			path = path[1:]
		}
		upi.DefaultUserPlanePath[selection.String()] = path
	}

	return pathExist
}

func (upi *UserPlaneInformation) GenerateDefaultPathToUPF(selection *UPFSelectionParams, destination *UPNode) bool {
	var source *UPNode

	for _, node := range upi.AccessNetwork {
		if node.Type == UPNODE_AN {
			source = node
			break
		}
	}

	if source == nil {
		logger.CtxLog.Errorf("There is no AN Node in config file!")
		return false
	}

	// Run DFS
	visited := make(map[*UPNode]bool)

	for _, upNode := range upi.UPNodes {
		visited[upNode] = false
	}

	path, pathExist := getPathBetween(source, destination, visited, selection)

	if pathExist {
		if path[0].Type == UPNODE_AN {
			path = path[1:]
		}
		if upi.DefaultUserPlanePathToUPF[selection.String()] == nil {
			upi.DefaultUserPlanePathToUPF[selection.String()] = make(map[string][]*UPNode)
		}
		upi.DefaultUserPlanePathToUPF[selection.String()][destination.NodeID.ResolveNodeIdToIp().String()] = path
	}

	return pathExist
}

func (upi *UserPlaneInformation) selectMatchUPF(selection *UPFSelectionParams) []*UPNode {
	upList := make([]*UPNode, 0)

	for _, upNode := range upi.UPFs {
		for _, snssaiInfo := range upNode.UPF.SNssaiInfos {
			currentSnssai := snssaiInfo.SNssai
			targetSnssai := selection.SNssai

			if currentSnssai.Equal(targetSnssai) {
				for _, dnnInfo := range snssaiInfo.DnnList {
					if dnnInfo.Dnn == selection.Dnn && dnnInfo.ContainsDNAI(selection.Dnai) {
						upList = append(upList, upNode)
						break
					}
				}
			}
		}
	}
	return upList
}

func getPathBetween(cur *UPNode, dest *UPNode, visited map[*UPNode]bool,
	selection *UPFSelectionParams,
) (path []*UPNode, pathExist bool) {
	visited[cur] = true

	if reflect.DeepEqual(*cur, *dest) {
		path = make([]*UPNode, 0)
		path = append(path, cur)
		pathExist = true
		return path, pathExist
	}

	selectedSNssai := selection.SNssai

	for _, node := range cur.Links {
		if !visited[node] {
			if !node.UPF.isSupportSnssai(selectedSNssai) {
				visited[node] = true
				continue
			}

			path_tail, pathExistBuf := getPathBetween(node, dest, visited, selection)
			pathExist = pathExistBuf
			if pathExist {
				path = make([]*UPNode, 0)
				path = append(path, cur)
				path = append(path, path_tail...)

				return path, pathExist
			}
		}
	}

	return nil, false
}

// this function select PSA by SNSSAI, DNN and DNAI exlude IP
func (upi *UserPlaneInformation) selectAnchorUPF(source *UPNode, selection *UPFSelectionParams) []*UPNode {
	// UPFSelectionParams may have static IP, but we would not match static IP in "MatchedSelection" function
	upList := make([]*UPNode, 0)
	visited := make(map[*UPNode]bool)
	queue := make([]*UPNode, 0)
	selectionForIUPF := &UPFSelectionParams{
		Dnn:                    selection.Dnn,
		SNssai:                 selection.SNssai,
		Dnai:                   selection.Dnai,
		SelectedPDUSessionType: selection.SelectedPDUSessionType,
	}

	queue = append(queue, source)
	for {
		node := queue[0]
		queue = queue[1:]
		findNewNode := false
		visited[node] = true
		for _, link := range node.Links {
			if !visited[link] {
				if link.MatchedSelection(selectionForIUPF) {
					queue = append(queue, link)
					findNewNode = true
					break
				}
			}
		}
		if !findNewNode {
			// if new node is AN type not need to add upList
			if node.Type == UPNODE_UPF && node.MatchedSelection(selection) {
				upList = append(upList, node)
			}
		}

		if len(queue) == 0 {
			break
		}
	}
	return upList
}

func (upi *UserPlaneInformation) sortUPFListByName(upfList []*UPNode) []*UPNode {
	keys := make([]string, 0, len(upi.UPFs))
	for k := range upi.UPFs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sortedUpList := make([]*UPNode, 0)
	for _, name := range keys {
		for _, node := range upfList {
			if name == upi.GetUPFNameByIp(node.NodeID.ResolveNodeIdToIp().String()) {
				sortedUpList = append(sortedUpList, node)
			}
		}
	}
	return sortedUpList
}

func (upi *UserPlaneInformation) selectUPPathSource() (*UPNode, error) {
	// if multiple gNBs exist, select one according to some criterion
	for _, node := range upi.AccessNetwork {
		if node.Type == UPNODE_AN {
			return node, nil
		}
	}
	return nil, errors.New("AN Node not found")
}

// UEIPAllocationResult represents the result of dual-stack IP allocation
// WNC: Extended for Phase 2 dual-stack support
type UEIPAllocationResult struct {
	UPF             *UPNode
	IPv4Address     net.IP
	IPv6Address     net.IP
	UseStaticIPv4   bool
	UseStaticIPv6   bool
	AllocatedFamily uint8 // nasMessage.PDUSessionTypeIPv4/IPv6/IPv4IPv6
}

// SelectUPFAndAllocUEIP will return anchor UPF, allocated UE IP and use/not use static IP
// WNC: Enhanced for Phase 2 - handles IPv4-only, IPv6-only, and IPv4v6 requests with graceful downgrade
func (upi *UserPlaneInformation) SelectUPFAndAllocUEIP(selection *UPFSelectionParams) (*UPNode, net.IP, bool) {
	result := upi.SelectUPFAndAllocUEIPDualStack(selection)
	if result == nil {
		return nil, nil, false
	}

	// For backward compatibility, return the first allocated address
	// Prefer IPv4 for legacy code paths
	if result.IPv4Address != nil {
		return result.UPF, result.IPv4Address, result.UseStaticIPv4
	}
	if result.IPv6Address != nil {
		return result.UPF, result.IPv6Address, result.UseStaticIPv6
	}
	return nil, nil, false
}

// SelectUPFAndAllocUEIPDualStack performs dual-stack aware IP allocation with graceful downgrade
// WNC: New Phase 2 function - implements requirement 2.2.1 from implementation plan
func (upi *UserPlaneInformation) SelectUPFAndAllocUEIPDualStack(selection *UPFSelectionParams) *UEIPAllocationResult {
	source, err := upi.selectUPPathSource()
	if err != nil {
		logger.CtxLog.Errorf("WNC: Failed to select UP path source: %v", err)
		return nil
	}

	UPFList := upi.selectAnchorUPF(source, selection)
	listLength := len(UPFList)
	if listLength == 0 {
		logger.CtxLog.Warnf("WNC: Can't find UPF with DNN[%s] S-NSSAI[sst: %d sd: %s] DNAI[%s]", selection.Dnn,
			selection.SNssai.Sst, selection.SNssai.Sd, selection.Dnai)
		return nil
	}

	// Determine required address families based on session type
	sessionType := selection.SelectedPDUSessionType
	if sessionType == 0 {
		sessionType = nasMessage.PDUSessionTypeIPv4 // Default to IPv4 for backward compatibility
	}

	needIPv4 := sessionType == nasMessage.PDUSessionTypeIPv4 ||
		sessionType == nasMessage.PDUSessionTypeIPv4IPv6
	needIPv6 := sessionType == nasMessage.PDUSessionTypeIPv6 ||
		sessionType == nasMessage.PDUSessionTypeIPv4IPv6

	logger.CtxLog.Infof("WNC: UE IP allocation request - Session type: 0x%02x, Need IPv4: %v, Need IPv6: %v",
		sessionType, needIPv4, needIPv6)

	UPFList = upi.sortUPFListByName(UPFList)
	sortedUPFList := createUPFListForSelection(UPFList)

	// Track best fallback candidates while searching for optimal match
	var bestIPv4Fallback *UEIPAllocationResult
	var bestIPv6Fallback *UEIPAllocationResult

	// Helper function to release all fallback allocations
	releaseFallbacks := func() {
		if bestIPv4Fallback != nil && bestIPv4Fallback.IPv4Address != nil {
			logger.CtxLog.Debugf("WNC: Releasing unused IPv4 fallback: %s", bestIPv4Fallback.IPv4Address)
			upi.ReleaseUEIP(bestIPv4Fallback.UPF, bestIPv4Fallback.IPv4Address, bestIPv4Fallback.UseStaticIPv4)
		}
		if bestIPv6Fallback != nil && bestIPv6Fallback.IPv6Address != nil {
			logger.CtxLog.Debugf("WNC: Releasing unused IPv6 fallback: %s", bestIPv6Fallback.IPv6Address)
			upi.ReleaseUEIP(bestIPv6Fallback.UPF, bestIPv6Fallback.IPv6Address, bestIPv6Fallback.UseStaticIPv6)
		}
	}

	for _, upf := range sortedUPFList {
		upfName := upi.GetUPFNameByIp(upf.NodeID.ResolveNodeIdToIp().String())
		logger.CtxLog.Debugf("WNC: Checking UPF: %s", upfName)

		if err = upf.UPF.IsAssociated(); err != nil {
			logger.CtxLog.Infof("WNC: UPF %s not associated: %v", upfName, err)
			continue
		}

		// Attempt dual-stack allocation if requested
		if needIPv4 && needIPv6 {
			result := upi.tryDualStackAllocation(upf, selection)
			if result != nil {
				// Release all fallback allocations before returning
				releaseFallbacks()
				logger.CtxLog.Infof("WNC: Selected UPF %s with dual-stack: IPv4=%s, IPv6=%s",
					upfName, result.IPv4Address, result.IPv6Address)
				return result
			}
			logger.CtxLog.Debugf("WNC: Dual-stack allocation failed for UPF %s, continuing search", upfName)

			// Track fallback candidates but continue searching for dual-stack
			if bestIPv4Fallback == nil {
				result = upi.trySingleFamilyAllocation(upf, selection, true)
				if result != nil {
					logger.CtxLog.Debugf("WNC: UPF %s has IPv4-only available as fallback candidate", upfName)
					bestIPv4Fallback = result
				}
			}
			if bestIPv6Fallback == nil {
				result = upi.trySingleFamilyAllocation(upf, selection, false)
				if result != nil {
					logger.CtxLog.Debugf("WNC: UPF %s has IPv6-only available as fallback candidate", upfName)
					bestIPv6Fallback = result
				}
			}
		} else if needIPv4 {
			// IPv4-only allocation
			result := upi.trySingleFamilyAllocation(upf, selection, true)
			if result != nil {
				logger.CtxLog.Infof("WNC: Selected UPF %s with IPv4-only: %s", upfName, result.IPv4Address)
				return result
			}
			logger.CtxLog.Debugf("WNC: IPv4 allocation failed for UPF %s, trying next UPF", upfName)
		} else if needIPv6 {
			// IPv6-only allocation
			result := upi.trySingleFamilyAllocation(upf, selection, false)
			if result != nil {
				logger.CtxLog.Infof("WNC: Selected UPF %s with IPv6-only: %s", upfName, result.IPv6Address)
				return result
			}
			logger.CtxLog.Debugf("WNC: IPv6 allocation failed for UPF %s, trying next UPF", upfName)
		}
	}

	// If dual-stack was requested but not available, use best fallback
	if needIPv4 && needIPv6 {
		if bestIPv4Fallback != nil {
			// Release unused IPv6 fallback if we're using IPv4
			if bestIPv6Fallback != nil {
				logger.CtxLog.Debugf("WNC: Releasing unused IPv6 fallback: %s", bestIPv6Fallback.IPv6Address)
				upi.ReleaseUEIP(bestIPv6Fallback.UPF, bestIPv6Fallback.IPv6Address, bestIPv6Fallback.UseStaticIPv6)
			}
			upfName := upi.GetUPFNameByIp(bestIPv4Fallback.UPF.NodeID.ResolveNodeIdToIp().String())
			logger.CtxLog.Warnf("WNC: Dual-stack (IPv4v6) unavailable, downgrading to IPv4-only from UPF %s: %s. "+
				"Subscriber requested IPv4v6 but no UPF has both IPv4 AND IPv6 pools configured. "+
				"Check smfcfg.yaml and upfcfg.yaml for DNN[%s] S-NSSAI[sst:%d sd:%s] - ensure both ipv4Pools/staticIPv4Pools AND ipv6Pools/staticIPv6Pools are configured",
				upfName, bestIPv4Fallback.IPv4Address, selection.Dnn, selection.SNssai.Sst, selection.SNssai.Sd)
			return bestIPv4Fallback
		}
		if bestIPv6Fallback != nil {
			// Release unused IPv4 fallback if we're using IPv6
			if bestIPv4Fallback != nil {
				logger.CtxLog.Debugf("WNC: Releasing unused IPv4 fallback: %s", bestIPv4Fallback.IPv4Address)
				upi.ReleaseUEIP(bestIPv4Fallback.UPF, bestIPv4Fallback.IPv4Address, bestIPv4Fallback.UseStaticIPv4)
			}
			upfName := upi.GetUPFNameByIp(bestIPv6Fallback.UPF.NodeID.ResolveNodeIdToIp().String())
			logger.CtxLog.Warnf("WNC: Dual-stack (IPv4v6) unavailable, downgrading to IPv6-only from UPF %s: %s. "+
				"Subscriber requested IPv4v6 but no UPF has both IPv4 AND IPv6 pools configured. "+
				"Check smfcfg.yaml and upfcfg.yaml for DNN[%s] S-NSSAI[sst:%d sd:%s] - ensure both ipv4Pools/staticIPv4Pools AND ipv6Pools/staticIPv6Pools are configured",
				upfName, bestIPv6Fallback.IPv6Address, selection.Dnn, selection.SNssai.Sst, selection.SNssai.Sd)
			return bestIPv6Fallback
		}
	}

	// All UPFs exhausted
	logger.CtxLog.Warnf("WNC: UE IP pool exhausted for DNN[%s] S-NSSAI[sst: %d sd: %s] DNAI[%s] Session type: 0x%02x",
		selection.Dnn, selection.SNssai.Sst, selection.SNssai.Sd, selection.Dnai, sessionType)
	return nil
}

// tryDualStackAllocation attempts to allocate both IPv4 and IPv6 addresses from the same UPF
// WNC: Phase 2 - implements graceful downgrade when dual-stack not possible
func (upi *UserPlaneInformation) tryDualStackAllocation(upf *UPNode, selection *UPFSelectionParams) *UEIPAllocationResult {
	// Get separate IPv4 and IPv6 pools
	ipv4Pools, useStaticIPv4 := upi.getUEIPPoolByFamily(upf, selection, true)
	ipv6Pools, useStaticIPv6 := upi.getUEIPPoolByFamily(upf, selection, false)

	if len(ipv4Pools) == 0 || len(ipv6Pools) == 0 {
		upfName := upi.GetUPFNameByIp(upf.NodeID.ResolveNodeIdToIp().String())
		logger.CtxLog.Warnf("WNC: Dual-stack not available for UPF %s - IPv4 pools: %d, IPv6 pools: %d. "+
			"Check smfcfg.yaml and upfcfg.yaml for DNN[%s] S-NSSAI[sst:%d sd:%s] pool configuration (both ipv6Pools and staticIPv6Pools)",
			upfName, len(ipv4Pools), len(ipv6Pools), selection.Dnn, selection.SNssai.Sst, selection.SNssai.Sd)
		return nil
	}

	// Try to allocate from both families
	var ipv4Addr, ipv6Addr net.IP

	// Allocate IPv4 first
	sortedIPv4Pools := createPoolListForSelection(ipv4Pools)
	for _, pool := range sortedIPv4Pools {
		addr := pool.Allocate(selection.PDUAddress)
		if addr != nil {
			ipv4Addr = addr
			logger.CtxLog.Debugf("WNC: Allocated IPv4: %s", addr)
			break
		}
	}

	if ipv4Addr == nil {
		logger.CtxLog.Debugf("WNC: Failed to allocate IPv4 for dual-stack")
		return nil
	}

	// Allocate IPv6
	// WNC: Pass static IPv6 if configured (Phase 2)
	staticIPv6 := selection.PDUAddressIPv6
	if staticIPv6 == nil && selection.PDUAddress != nil && selection.PDUAddress.To4() == nil {
		staticIPv6 = selection.PDUAddress
	}

	sortedIPv6Pools := createPoolListForSelection(ipv6Pools)
	for _, pool := range sortedIPv6Pools {
		addr := pool.Allocate(staticIPv6)
		if addr != nil {
			ipv6Addr = addr
			logger.CtxLog.Debugf("WNC: Allocated IPv6: %s", addr)
			break
		}
	}

	if ipv6Addr == nil {
		// Release IPv4 and fail dual-stack attempt
		// Caller will attempt IPv4-only fallback on the same UPF
		logger.CtxLog.Warnf("WNC: Failed to allocate IPv6 for dual-stack, releasing IPv4 %s", ipv4Addr)
		upi.ReleaseUEIP(upf, ipv4Addr, useStaticIPv4)
		return nil
	}

	// Success: both addresses allocated
	return &UEIPAllocationResult{
		UPF:             upf,
		IPv4Address:     ipv4Addr,
		IPv6Address:     ipv6Addr,
		UseStaticIPv4:   useStaticIPv4,
		UseStaticIPv6:   useStaticIPv6,
		AllocatedFamily: nasMessage.PDUSessionTypeIPv4IPv6,
	}
}

// trySingleFamilyAllocation attempts to allocate a single address family (IPv4 or IPv6)
// WNC: Phase 2 - single family allocation for IPv4-only or IPv6-only sessions
func (upi *UserPlaneInformation) trySingleFamilyAllocation(upf *UPNode, selection *UPFSelectionParams, isIPv4 bool) *UEIPAllocationResult {
	pools, useStatic := upi.getUEIPPoolByFamily(upf, selection, isIPv4)
	if len(pools) == 0 {
		logger.CtxLog.Debugf("WNC: No %s pools available", map[bool]string{true: "IPv4", false: "IPv6"}[isIPv4])
		return nil
	}

	sortedPoolList := createPoolListForSelection(pools)
	for _, pool := range sortedPoolList {
		var addr net.IP
		if isIPv4 {
			addr = pool.Allocate(selection.PDUAddress)
		} else {
			// WNC: For IPv6, pass the static IPv6 address if configured (Phase 2)
			staticIPv6 := selection.PDUAddressIPv6
			if staticIPv6 == nil && selection.PDUAddress != nil && selection.PDUAddress.To4() == nil {
				staticIPv6 = selection.PDUAddress
			}
			addr = pool.Allocate(staticIPv6)
		}

		if addr != nil {
			result := &UEIPAllocationResult{
				UPF: upf,
			}
			if isIPv4 {
				result.IPv4Address = addr
				result.UseStaticIPv4 = useStatic
				result.AllocatedFamily = nasMessage.PDUSessionTypeIPv4
			} else {
				result.IPv6Address = addr
				result.UseStaticIPv6 = useStatic
				result.AllocatedFamily = nasMessage.PDUSessionTypeIPv6
			}
			return result
		}
	}

	logger.CtxLog.Debugf("WNC: %s pool exhausted for this UPF", map[bool]string{true: "IPv4", false: "IPv6"}[isIPv4])
	return nil
}

// getUEIPPoolByFamily returns IP pools for a specific address family (IPv4 or IPv6)
// WNC: Phase 2 - helper function to separate pool selection by family
func (upi *UserPlaneInformation) getUEIPPoolByFamily(upNode *UPNode, selection *UPFSelectionParams, isIPv4 bool) ([]*UeIPPool, bool) {
	for _, snssaiInfo := range upNode.UPF.SNssaiInfos {
		if !snssaiInfo.SNssai.Equal(selection.SNssai) {
			continue
		}

		for _, dnnInfo := range snssaiInfo.DnnList {
			if dnnInfo.Dnn != selection.Dnn {
				continue
			}
			if selection.Dnai != "" && !dnnInfo.ContainsDNAI(selection.Dnai) {
				continue
			}

			var candidatePools []*UeIPPool
			var useStatic bool

			if isIPv4 {
				// Check for static IPv4 assignment first
				if selection.PDUAddress != nil && selection.PDUAddress.To4() != nil {
					// Static IP requested
					for _, pool := range dnnInfo.StaticIPPools {
						if pool.ueSubNet.Contains(selection.PDUAddress) {
							return []*UeIPPool{pool}, true
						}
					}
					// Fall back to dynamic pools if static not found
					for _, pool := range dnnInfo.UeIPPools {
						if pool.ueSubNet.Contains(selection.PDUAddress) {
							logger.CtxLog.Infof("WNC: Static IPv4 not found, using dynamic pool")
							return []*UeIPPool{pool}, false
						}
					}
					return nil, false
				}
				// Dynamic IPv4 allocation
				candidatePools = dnnInfo.UeIPPools
				useStatic = false
			} else {
				// IPv6 allocation - check static assignments first (Phase 2)
				// Precedence: static bind (IPv6StaticAssignments) > static pool > dynamic pool

				// Check if this is a static IPv6 bind from IPv6StaticAssignments
				// WNC: Check both PDUAddressIPv6 (new field) and PDUAddress (legacy compatibility)
				staticIPv6 := selection.PDUAddressIPv6
				if staticIPv6 == nil && selection.PDUAddress != nil && selection.PDUAddress.To4() == nil {
					staticIPv6 = selection.PDUAddress
				}

				if staticIPv6 != nil {
					// IPv6 address provided - check static assignments first
					for _, assignment := range dnnInfo.IPv6StaticAssignments {
						assignedIP := net.ParseIP(assignment.Address)
						if assignedIP != nil && assignedIP.Equal(staticIPv6) {
							logger.CtxLog.Infof("WNC: Static IPv6 bind found in IPv6StaticAssignments: %s", assignment.Address)
							// Create a pseudo-pool to return this specific address
							// This ensures the allocator validates and uses the static assignment
							for _, pool := range dnnInfo.StaticIPv6Pools {
								if pool.ueSubNet.Contains(assignedIP) {
									return []*UeIPPool{pool}, true
								}
							}
							// If not in static pools, check dynamic pools
							for _, pool := range dnnInfo.UeIPv6Pools {
								if pool.ueSubNet.Contains(assignedIP) {
									logger.CtxLog.Infof("WNC: Static IPv6 assignment found in dynamic pool")
									return []*UeIPPool{pool}, false
								}
							}
							return nil, false
						}
					}

					// Check static IPv6 pools
					for _, pool := range dnnInfo.StaticIPv6Pools {
						if pool.ueSubNet.Contains(staticIPv6) {
							logger.CtxLog.Infof("WNC: Static IPv6 found in static pool")
							return []*UeIPPool{pool}, true
						}
					}

					// Fall back to dynamic pools if static not found
					for _, pool := range dnnInfo.UeIPv6Pools {
						if pool.ueSubNet.Contains(staticIPv6) {
							logger.CtxLog.Infof("WNC: Static IPv6 not found, using dynamic pool")
							return []*UeIPPool{pool}, false
						}
					}
					return nil, false
				}

				// Dynamic IPv6 allocation
				candidatePools = dnnInfo.UeIPv6Pools
				useStatic = false
			}

			return candidatePools, useStatic
		}
	}
	return nil, false
}

// SelectUPFWithoutAllocUEIP selects UPF without allocating IP address (for non-IP sessions)
func (upi *UserPlaneInformation) SelectUPFWithoutAllocUEIP(selection *UPFSelectionParams) *UPNode {
	source, err := upi.selectUPPathSource()
	if err != nil {
		return nil
	}
	UPFList := upi.selectAnchorUPF(source, selection)
	listLength := len(UPFList)
	if listLength == 0 {
		logger.CtxLog.Warnf("WNC: Can't find UPF with DNN[%s] S-NSSAI[sst: %d sd: %s] DNAI[%s]\n", selection.Dnn,
			selection.SNssai.Sst, selection.SNssai.Sd, selection.Dnai)
		return nil
	}
	UPFList = upi.sortUPFListByName(UPFList)
	sortedUPFList := createUPFListForSelection(UPFList)
	for _, upf := range sortedUPFList {
		logger.CtxLog.Debugf("WNC: check start UPF: %s",
			upi.GetUPFNameByIp(upf.NodeID.ResolveNodeIdToIp().String()))
		if err = upf.UPF.IsAssociated(); err != nil {
			logger.CtxLog.Infoln(err)
			continue
		}
		// For non-IP sessions, just verify UPF matches selection criteria (no pool check needed)
		logger.CtxLog.Infof("WNC: Selected UPF: %s (non-IP session)",
			upi.GetUPFNameByIp(upf.NodeID.ResolveNodeIdToIp().String()))
		return upf
	}
	// checked all UPFs
	logger.CtxLog.Warnf("WNC: No associated UPF found for DNN[%s] S-NSSAI[sst: %d sd: %s] DNAI[%s]\n", selection.Dnn,
		selection.SNssai.Sst, selection.SNssai.Sd, selection.Dnai)
	return nil
}

func createUPFListForSelection(inputList []*UPNode) (outputList []*UPNode) {
	offset := rand.Intn(len(inputList))
	return append(inputList[offset:], inputList[:offset]...)
}

func createPoolListForSelection(inputList []*UeIPPool) (outputList []*UeIPPool) {
	offset := rand.Intn(len(inputList))
	return append(inputList[offset:], inputList[:offset]...)
}

// getUEIPPool will return IP pools and use/not use static IP pool
func getUEIPPool(upNode *UPNode, selection *UPFSelectionParams) ([]*UeIPPool, bool) {
	for _, snssaiInfo := range upNode.UPF.SNssaiInfos {
		currentSnssai := snssaiInfo.SNssai
		targetSnssai := selection.SNssai

		if currentSnssai.Equal(targetSnssai) {
			for _, dnnInfo := range snssaiInfo.DnnList {
				if dnnInfo.Dnn == selection.Dnn {
					if selection.Dnai != "" && !dnnInfo.ContainsDNAI(selection.Dnai) {
						continue
					}

					// Determine address family based on session type
					// Default to IPv4 for backward compatibility when SelectedPDUSessionType == 0
					sessionType := selection.SelectedPDUSessionType
					if sessionType == 0 {
						sessionType = nasMessage.PDUSessionTypeIPv4
					}

					needIPv4 := sessionType == nasMessage.PDUSessionTypeIPv4 ||
						sessionType == nasMessage.PDUSessionTypeIPv4IPv6
					needIPv6 := sessionType == nasMessage.PDUSessionTypeIPv6 ||
						sessionType == nasMessage.PDUSessionTypeIPv4IPv6

					// WNC: Check both PDUAddress (IPv4) and PDUAddressIPv6 (IPv6 static bindings)
					// This ensures ULCL path honors static IPv6 assignments
					staticIPv4 := selection.PDUAddress
					staticIPv6 := selection.PDUAddressIPv6

					// Legacy compatibility: if PDUAddress is IPv6, use it as staticIPv6
					if staticIPv4 != nil && staticIPv4.To4() == nil {
						staticIPv6 = staticIPv4
						staticIPv4 = nil
					}

					// WNC: Handle static allocations independently per family
					// This allows one family to use dynamic pools even when the other has static assignment
					hasStaticIPv4 := needIPv4 && staticIPv4 != nil
					hasStaticIPv6 := needIPv6 && staticIPv6 != nil

					// Try static IPv4 allocation if configured
					if hasStaticIPv4 {
						// Check IPv4 static pools
						for _, ueIPPool := range dnnInfo.StaticIPPools {
							if ueIPPool.ueSubNet.Contains(staticIPv4) {
								logger.CfgLog.Infof("WNC: ULCL using IPv4 static pool for address %s", staticIPv4)
								return []*UeIPPool{ueIPPool}, true
							}
						}
						// Check IPv4 dynamic pools
						for _, ueIPPool := range dnnInfo.UeIPPools {
							if ueIPPool.ueSubNet.Contains(staticIPv4) {
								logger.CfgLog.Infof("WNC: ULCL cannot find selected IPv4 in static pool[%v], use dynamic pool[%+v]",
									dnnInfo.StaticIPPools, dnnInfo.UeIPPools)
								return []*UeIPPool{ueIPPool}, false
							}
						}
						// Static IPv4 was requested but not found in any pool
						logger.CfgLog.Warnf("WNC: Static IPv4 %s not found in any pool for DNN %s", staticIPv4, selection.Dnn)
					}

					// Try static IPv6 allocation if configured
					if hasStaticIPv6 {
						// Check IPv6 static pools
						for _, ueIPPool := range dnnInfo.StaticIPv6Pools {
							if ueIPPool.ueSubNet.Contains(staticIPv6) {
								logger.CfgLog.Infof("WNC: ULCL using IPv6 static pool for address %s", staticIPv6)
								return []*UeIPPool{ueIPPool}, true
							}
						}
						// Check IPv6 dynamic pools
						for _, ueIPPool := range dnnInfo.UeIPv6Pools {
							if ueIPPool.ueSubNet.Contains(staticIPv6) {
								logger.CfgLog.Infof("WNC: ULCL cannot find selected IPv6 address in static pool[%v], using dynamic pool[%+v]",
									dnnInfo.StaticIPv6Pools, dnnInfo.UeIPv6Pools)
								return []*UeIPPool{ueIPPool}, false
							}
						}
						// Static IPv6 was requested but not found in any pool
						logger.CfgLog.Warnf("WNC: Static IPv6 %s not found in any pool for DNN %s", staticIPv6, selection.Dnn)
					}

					// WNC: If we had a static assignment that wasn't found, don't fall back to dynamic
					// This preserves the original behavior of returning nil when static IP is configured but not in pool
					if hasStaticIPv4 || hasStaticIPv6 {
						return nil, false
					}

					// Dynamic allocation case - no specific PDU address or static assignment not found
					var candidatePools []*UeIPPool

					if needIPv4 {
						candidatePools = append(candidatePools, dnnInfo.UeIPPools...)
					}
					if needIPv6 {
						candidatePools = append(candidatePools, dnnInfo.UeIPv6Pools...)
					}

					return candidatePools, false
				}
			}
		}
	}
	return nil, false
}

// ReleaseUEIP releases a UE IP address back to the pool
// WNC: Enhanced for Phase 2 - handles both IPv4 and IPv6 addresses
func (upi *UserPlaneInformation) ReleaseUEIP(upf *UPNode, addr net.IP, static bool) {
	if addr == nil {
		return
	}

	pool := findPoolByAddr(upf, addr, static)
	if pool == nil {
		// nothing to do
		upfName := upi.GetUPFNameByIp(upf.NodeID.ResolveNodeIdToIp().String())
		logger.CtxLog.Warnf("WNC: Fail to release UE IP address %s to UPF %s (static: %v)",
			addr, upfName, static)
		return
	}
	pool.Release(addr)

	// WNC: Log IPv6 releases explicitly for troubleshooting
	if addr.To4() == nil {
		logger.CtxLog.Infof("WNC: Released IPv6 address %s", addr)
	}
}

func findPoolByAddr(upf *UPNode, addr net.IP, static bool) *UeIPPool {
	for _, snssaiInfo := range upf.UPF.SNssaiInfos {
		for _, dnnInfo := range snssaiInfo.DnnList {
			// Check IPv4 pools
			if static {
				for _, pool := range dnnInfo.StaticIPPools {
					if pool.ueSubNet.Contains(addr) {
						return pool
					}
				}
			} else {
				for _, pool := range dnnInfo.UeIPPools {
					if pool.ueSubNet.Contains(addr) {
						return pool
					}
				}
			}

			// Check IPv6 pools
			if static {
				for _, pool := range dnnInfo.StaticIPv6Pools {
					if pool.ueSubNet.Contains(addr) {
						return pool
					}
				}
			} else {
				for _, pool := range dnnInfo.UeIPv6Pools {
					if pool.ueSubNet.Contains(addr) {
						return pool
					}
				}
			}
		}
	}
	return nil
}
