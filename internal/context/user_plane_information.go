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
						Dnn:                   dnnInfoConfig.Dnn,
						DnaiList:              dnnInfoConfig.DnaiList,
						PduSessionTypes:       dnnInfoConfig.PduSessionTypes,
						UeIPPools:             ueIPPools,
						StaticIPPools:         staticUeIPPools,
						UeIPv6Pools:           ipv6Pools,
						StaticIPv6Pools:       ipv6StaticPools,
						IPv6StaticAssignments: ipv6StaticAssignments,
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
						Dnn:                   dnnInfoConfig.Dnn,
						DnaiList:              dnnInfoConfig.DnaiList,
						PduSessionTypes:       dnnInfoConfig.PduSessionTypes,
						UeIPPools:             ueIPPools,
						StaticIPPools:         staticUeIPPools,
						UeIPv6Pools:           ipv6Pools,
						StaticIPv6Pools:       ipv6StaticPools,
						IPv6StaticAssignments: ipv6StaticAssignments,
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

// SelectUPFAndAllocUEIP will return anchor UPF, allocated UE IP and use/not use static IP
func (upi *UserPlaneInformation) SelectUPFAndAllocUEIP(selection *UPFSelectionParams) (*UPNode, net.IP, bool) {
	source, err := upi.selectUPPathSource()
	if err != nil {
		return nil, nil, false
	}
	UPFList := upi.selectAnchorUPF(source, selection)
	listLength := len(UPFList)
	if listLength == 0 {
		logger.CtxLog.Warnf("Can't find UPF with DNN[%s] S-NSSAI[sst: %d sd: %s] DNAI[%s]\n", selection.Dnn,
			selection.SNssai.Sst, selection.SNssai.Sd, selection.Dnai)
		return nil, nil, false
	}
	UPFList = upi.sortUPFListByName(UPFList)
	sortedUPFList := createUPFListForSelection(UPFList)
	for _, upf := range sortedUPFList {
		logger.CtxLog.Debugf("check start UPF: %s",
			upi.GetUPFNameByIp(upf.NodeID.ResolveNodeIdToIp().String()))
		if err = upf.UPF.IsAssociated(); err != nil {
			logger.CtxLog.Infoln(err)
			continue
		}

		pools, useStaticIPPool := getUEIPPool(upf, selection)
		if len(pools) == 0 {
			continue
		}
		sortedPoolList := createPoolListForSelection(pools)
		for _, pool := range sortedPoolList {
			logger.CtxLog.Debugf("check start UEIPPool(%+v)", pool.ueSubNet)
			addr := pool.Allocate(selection.PDUAddress)
			if addr != nil {
				logger.CtxLog.Infof("Selected UPF: %s",
					upi.GetUPFNameByIp(upf.NodeID.ResolveNodeIdToIp().String()))
				return upf, addr, useStaticIPPool
			}
			// if all addresses in pool are used, search next pool
			logger.CtxLog.Debug("check next pool")
		}
		// if all addresses in UPF are used, search next UPF
		logger.CtxLog.Debug("check next upf")
	}
	// checked all UPFs
	logger.CtxLog.Warnf("UE IP pool exhausted for DNN[%s] S-NSSAI[sst: %d sd: %s] DNAI[%s]\n", selection.Dnn,
		selection.SNssai.Sst, selection.SNssai.Sd, selection.Dnai)
	return nil, nil, false
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

					if selection.PDUAddress != nil {
						// Static IP allocation case
						if needIPv4 {
							// Check IPv4 static pools
							for _, ueIPPool := range dnnInfo.StaticIPPools {
								if ueIPPool.ueSubNet.Contains(selection.PDUAddress) {
									return []*UeIPPool{ueIPPool}, true
								}
							}
							// Check IPv4 dynamic pools
							for _, ueIPPool := range dnnInfo.UeIPPools {
								if ueIPPool.ueSubNet.Contains(selection.PDUAddress) {
									logger.CfgLog.Infof("cannot find selected IP in static pool[%v], use dynamic pool[%+v]",
										dnnInfo.StaticIPPools, dnnInfo.UeIPPools)
									return []*UeIPPool{ueIPPool}, false
								}
							}
						}

						if needIPv6 {
							// Check IPv6 static pools
							for _, ueIPPool := range dnnInfo.StaticIPv6Pools {
								if ueIPPool.ueSubNet.Contains(selection.PDUAddress) {
									logger.CfgLog.Infof("WNC: Using IPv6 static pool for address %s", selection.PDUAddress)
									return []*UeIPPool{ueIPPool}, true
								}
							}
							// Check IPv6 dynamic pools
							for _, ueIPPool := range dnnInfo.UeIPv6Pools {
								if ueIPPool.ueSubNet.Contains(selection.PDUAddress) {
									logger.CfgLog.Infof("WNC: Cannot find selected IPv6 address in static pool[%v], using dynamic pool[%+v]",
										dnnInfo.StaticIPv6Pools, dnnInfo.UeIPv6Pools)
									return []*UeIPPool{ueIPPool}, false
								}
							}
						}

						return nil, false
					}

					// Dynamic allocation case - no specific PDU address
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

func (upi *UserPlaneInformation) ReleaseUEIP(upf *UPNode, addr net.IP, static bool) {
	pool := findPoolByAddr(upf, addr, static)
	if pool == nil {
		// nothing to do
		logger.CtxLog.Warnf("Fail to release UE IP address: %v to UPF: %s",
			upi.GetUPFNameByIp(upf.NodeID.ResolveNodeIdToIp().String()), addr)
		return
	}
	pool.Release(addr)
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
