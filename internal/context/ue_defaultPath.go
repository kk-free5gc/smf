package context

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"

	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/smf/internal/logger"
	"github.com/free5gc/smf/pkg/factory"
)

type UEDefaultPaths struct {
	AnchorUPFs      []string // list of UPF name
	DefaultPathPool DefaultPathPool
}

type DefaultPathPool map[string]*DataPath // key: UPF name

func NewUEDefaultPaths(upi *UserPlaneInformation, topology []factory.UPLink) (*UEDefaultPaths, error) {
	logger.MainLog.Traceln("In NewUEDefaultPaths")

	defaultPathPool := make(map[string]*DataPath)
	source, err := findSourceInTopology(upi, topology)
	if err != nil {
		return nil, err
	}
	destinations, err := extractAnchorUPFForULCL(upi, source, topology)
	if err != nil {
		return nil, err
	}
	for _, destination := range destinations {
		path, errgenerate := generateDefaultDataPath(source, destination, topology)
		if errgenerate != nil {
			return nil, errgenerate
		}
		defaultPathPool[destination] = path
	}
	defautlPaths := &UEDefaultPaths{
		AnchorUPFs:      destinations,
		DefaultPathPool: defaultPathPool,
	}
	return defautlPaths, nil
}

func findSourceInTopology(upi *UserPlaneInformation, topology []factory.UPLink) (string, error) {
	sourceList := make([]string, 0)
	for key, node := range upi.AccessNetwork {
		if node.Type == UPNODE_AN {
			sourceList = append(sourceList, key)
		}
	}
	for _, anName := range sourceList {
		for _, link := range topology {
			if link.A == anName || link.B == anName {
				// if multiple gNBs exist, select one according to some criterion
				logger.InitLog.Debugf("%s is AN", anName)
				return anName, nil
			}
		}
	}
	return "", errors.New("Not found AN node in topology")
}

func extractAnchorUPFForULCL(upi *UserPlaneInformation, source string, topology []factory.UPLink) ([]string, error) {
	upList := make([]string, 0)
	visited := make(map[string]bool)
	queue := make([]string, 0)

	queue = append(queue, source)
	queued := make(map[string]bool)
	queued[source] = true

	for {
		node := queue[0]
		queue = queue[1:]
		findNewLink := false
		for _, link := range topology {
			if link.A == node {
				if !queued[link.B] {
					queue = append(queue, link.B)
					queued[link.B] = true
					findNewLink = true
				}
				if !visited[link.B] {
					findNewLink = true
				}
			}
			if link.B == node {
				if !queued[link.A] {
					queue = append(queue, link.A)
					queued[link.A] = true
					findNewLink = true
				}
				if !visited[link.A] {
					findNewLink = true
				}
			}
		}
		visited[node] = true
		if !findNewLink {
			logger.InitLog.Debugf("%s is Anchor UPF", node)
			upList = append(upList, node)
		}
		if len(queue) == 0 {
			break
		}
	}
	if len(upList) == 0 {
		return nil, errors.New("Not found Anchor UPF in topology")
	}
	sort.Strings(upList)
	return upList, nil
}

func generateDefaultDataPath(source string, destination string, topology []factory.UPLink) (*DataPath, error) {
	allPaths, _ := getAllPathByNodeName(source, destination, topology)
	if len(allPaths) == 0 {
		return nil, fmt.Errorf("Path not exist: %s to %s", source, destination)
	}

	dataPath := NewDataPath()
	lowerBound := 0
	var parentNode *DataPathNode = nil

	// if multiple Paths exist, select one according to some criterion
	for idx, nodeName := range allPaths[0] {
		newUeNode, err := NewUEDataPathNode(nodeName)
		if err != nil {
			return nil, err
		}
		if idx == lowerBound {
			dataPath.FirstDPNode = newUeNode
		}
		if parentNode != nil {
			newUeNode.AddPrev(parentNode)
			parentNode.AddNext(newUeNode)
		}
		parentNode = newUeNode
	}
	logger.CtxLog.Tracef("New default data path (%s to %s): ", source, destination)
	logger.CtxLog.Traceln("\n" + dataPath.String() + "\n")
	return dataPath, nil
}

func getAllPathByNodeName(src, dest string, links []factory.UPLink) (map[int][]string, int) {
	visited := make(map[string]bool)
	allPaths := make(map[int][]string)
	count := 0
	var findPath func(src, dest string, links []factory.UPLink, currentPath []string)

	findPath = func(src, dest string, links []factory.UPLink, currentPath []string) {
		if visited[src] {
			return
		}
		visited[src] = true
		currentPath = append(currentPath, src)
		logger.InitLog.Traceln("current path:", currentPath)
		if src == dest {
			cpy := make([]string, len(currentPath))
			copy(cpy, currentPath)
			allPaths[count] = cpy[1:]
			count++
			logger.InitLog.Traceln("all path:", allPaths)
			visited[src] = false
			return
		}
		for _, link := range links {
			// search A to B only
			if link.A == src {
				findPath(link.B, dest, links, currentPath)
			}
		}
		visited[src] = false
	}

	findPath(src, dest, links, []string{})
	return allPaths, count
}

func createUPFListForSelectionULCL(inputList []string) (outputList []string) {
	offset := rand.Intn(len(inputList))
	return append(inputList[offset:], inputList[:offset]...)
}

// SelectUPFAndAllocUEIPForULCL selects UPF and allocates IP(s) for ULCL with dual-stack support
// WNC: Updated to return UEIPAllocationResult for dual-stack compatibility
func (dfp *UEDefaultPaths) SelectUPFAndAllocUEIPForULCL(upi *UserPlaneInformation,
	selection *UPFSelectionParams,
) *UEIPAllocationResult {
	sortedUPFList := createUPFListForSelectionULCL(dfp.AnchorUPFs)

	// Determine required address families based on session type
	sessionType := selection.SelectedPDUSessionType
	if sessionType == 0 {
		sessionType = nasMessage.PDUSessionTypeIPv4 // Default to IPv4 for backward compatibility
	}

	needIPv4 := sessionType == nasMessage.PDUSessionTypeIPv4 ||
		sessionType == nasMessage.PDUSessionTypeIPv4IPv6
	needIPv6 := sessionType == nasMessage.PDUSessionTypeIPv6 ||
		sessionType == nasMessage.PDUSessionTypeIPv4IPv6

	logger.CtxLog.Infof("WNC: ULCL IP allocation request - Session type: 0x%02x, Need IPv4: %v, Need IPv6: %v",
		sessionType, needIPv4, needIPv6)

	// Track best fallback candidates for dual-stack downgrade
	var bestIPv4Fallback *UEIPAllocationResult
	var bestIPv6Fallback *UEIPAllocationResult

	// Helper to release fallback allocations
	releaseFallbacks := func() {
		if bestIPv4Fallback != nil && bestIPv4Fallback.IPv4Address != nil {
			logger.CtxLog.Debugf("WNC: ULCL releasing unused IPv4 fallback: %s", bestIPv4Fallback.IPv4Address)
			upi.ReleaseUEIP(bestIPv4Fallback.UPF, bestIPv4Fallback.IPv4Address, bestIPv4Fallback.UseStaticIPv4)
		}
		if bestIPv6Fallback != nil && bestIPv6Fallback.IPv6Address != nil {
			logger.CtxLog.Debugf("WNC: ULCL releasing unused IPv6 fallback: %s", bestIPv6Fallback.IPv6Address)
			upi.ReleaseUEIP(bestIPv6Fallback.UPF, bestIPv6Fallback.IPv6Address, bestIPv6Fallback.UseStaticIPv6)
		}
	}

	for _, upfName := range sortedUPFList {
		logger.CtxLog.Debugf("WNC: ULCL checking UPF: %s", upfName)
		upf := upi.UPFs[upfName]

		// Attempt dual-stack allocation if both families are needed
		if needIPv4 && needIPv6 {
			result := tryULCLDualStackAllocation(upi, upf, selection)
			if result != nil {
				releaseFallbacks()
				logger.CtxLog.Infof("WNC: ULCL selected UPF %s with dual-stack: IPv4=%s, IPv6=%s",
					upfName, result.IPv4Address, result.IPv6Address)
				return result
			}
			logger.CtxLog.Debugf("WNC: ULCL dual-stack allocation failed for UPF %s, continuing search", upfName)

			// Track fallback candidates
			if bestIPv4Fallback == nil {
				result = tryULCLSingleFamilyAllocation(upi, upf, selection, true)
				if result != nil {
					logger.CtxLog.Debugf("WNC: ULCL UPF %s has IPv4-only available as fallback", upfName)
					bestIPv4Fallback = result
				}
			}
			if bestIPv6Fallback == nil {
				result = tryULCLSingleFamilyAllocation(upi, upf, selection, false)
				if result != nil {
					logger.CtxLog.Debugf("WNC: ULCL UPF %s has IPv6-only available as fallback", upfName)
					bestIPv6Fallback = result
				}
			}
		} else if needIPv4 {
			// IPv4-only allocation
			result := tryULCLSingleFamilyAllocation(upi, upf, selection, true)
			if result != nil {
				logger.CtxLog.Infof("WNC: ULCL selected UPF %s with IPv4-only: %s", upfName, result.IPv4Address)
				return result
			}
			logger.CtxLog.Debugf("WNC: ULCL IPv4 allocation failed for UPF %s, trying next UPF", upfName)
		} else if needIPv6 {
			// IPv6-only allocation
			result := tryULCLSingleFamilyAllocation(upi, upf, selection, false)
			if result != nil {
				logger.CtxLog.Infof("WNC: ULCL selected UPF %s with IPv6-only: %s", upfName, result.IPv6Address)
				return result
			}
			logger.CtxLog.Debugf("WNC: ULCL IPv6 allocation failed for UPF %s, trying next UPF", upfName)
		}
	}

	// If dual-stack was requested but not available, use best fallback
	if needIPv4 && needIPv6 {
		if bestIPv4Fallback != nil {
			if bestIPv6Fallback != nil {
				logger.CtxLog.Debugf("WNC: ULCL releasing unused IPv6 fallback: %s", bestIPv6Fallback.IPv6Address)
				upi.ReleaseUEIP(bestIPv6Fallback.UPF, bestIPv6Fallback.IPv6Address, bestIPv6Fallback.UseStaticIPv6)
			}
			upfName := upi.GetUPFNameByIp(bestIPv4Fallback.UPF.NodeID.ResolveNodeIdToIp().String())
			logger.CtxLog.Warnf("WNC: ULCL dual-stack unavailable, using IPv4-only fallback from UPF %s: %s",
				upfName, bestIPv4Fallback.IPv4Address)
			return bestIPv4Fallback
		}
		if bestIPv6Fallback != nil {
			if bestIPv4Fallback != nil {
				logger.CtxLog.Debugf("WNC: ULCL releasing unused IPv4 fallback: %s", bestIPv4Fallback.IPv4Address)
				upi.ReleaseUEIP(bestIPv4Fallback.UPF, bestIPv4Fallback.IPv4Address, bestIPv4Fallback.UseStaticIPv4)
			}
			upfName := upi.GetUPFNameByIp(bestIPv6Fallback.UPF.NodeID.ResolveNodeIdToIp().String())
			logger.CtxLog.Warnf("WNC: ULCL dual-stack unavailable, using IPv6-only fallback from UPF %s: %s",
				upfName, bestIPv6Fallback.IPv6Address)
			return bestIPv6Fallback
		}
	}

	// checked all UPFs
	logger.CtxLog.Warnf("WNC: ULCL UE IP pool exhausted for DNN[%s] S-NSSAI[sst: %d sd: %s] DNAI[%s]", selection.Dnn,
		selection.SNssai.Sst, selection.SNssai.Sd, selection.Dnai)
	return nil
}

// SelectUPFWithoutAllocUEIPForULCL selects UPF without allocating IP address (for non-IP sessions)
func (dfp *UEDefaultPaths) SelectUPFWithoutAllocUEIPForULCL(upi *UserPlaneInformation,
	selection *UPFSelectionParams,
) string {
	sortedUPFList := createUPFListForSelectionULCL(dfp.AnchorUPFs)

	for _, upfName := range sortedUPFList {
		logger.CtxLog.Debugf("WNC: check start UPF: %s", upfName)
		upf := upi.UPFs[upfName]

		if err := upf.UPF.IsAssociated(); err != nil {
			logger.CtxLog.Infoln(err)
			continue
		}

		// For non-IP sessions, just verify UPF is associated (no pool check needed)
		logger.CtxLog.Infof("WNC: Selected UPF: %s (non-IP session)", upfName)
		return upfName
	}
	// checked all UPFs
	logger.CtxLog.Warnf("WNC: No associated UPF found for DNN[%s] S-NSSAI[sst: %d sd: %s] DNAI[%s]\n", selection.Dnn,
		selection.SNssai.Sst, selection.SNssai.Sd, selection.Dnai)
	return ""
}

func (dfp *UEDefaultPaths) GetDefaultPath(upfName string) *DataPath {
	firstNode := dfp.DefaultPathPool[upfName].CopyFirstDPNode()
	dataPath := &DataPath{
		Activated:     false,
		IsDefaultPath: true,
		Destination:   dfp.DefaultPathPool[upfName].Destination,
		FirstDPNode:   firstNode,
	}
	return dataPath
}
// tryULCLDualStackAllocation attempts dual-stack allocation for ULCL
// WNC: ULCL-specific dual-stack allocation using getUEIPPool
func tryULCLDualStackAllocation(upi *UserPlaneInformation, upf *UPNode, selection *UPFSelectionParams) *UEIPAllocationResult {
	// Get pools for both families using the ULCL helper
	ipv4Pools, ipv6Pools, useStaticIPv4, useStaticIPv6 := getUEIPPoolDualStack(upf, selection)

	if len(ipv4Pools) == 0 || len(ipv6Pools) == 0 {
		logger.CtxLog.Debugf("WNC: ULCL dual-stack not available (IPv4 pools: %d, IPv6 pools: %d)",
			len(ipv4Pools), len(ipv6Pools))
		return nil
	}

	// Try to allocate from both families
	var ipv4Addr, ipv6Addr net.IP

	// Allocate IPv4 first
	sortedIPv4Pools := createPoolListForSelection(ipv4Pools)
	staticIPv4 := selection.PDUAddress
	if staticIPv4 != nil && staticIPv4.To4() == nil {
		staticIPv4 = nil // Not IPv4
	}
	for _, pool := range sortedIPv4Pools {
		addr := pool.Allocate(staticIPv4)
		if addr != nil {
			ipv4Addr = addr
			logger.CtxLog.Debugf("WNC: ULCL allocated IPv4: %s", addr)
			break
		}
	}

	if ipv4Addr == nil {
		logger.CtxLog.Debugf("WNC: ULCL failed to allocate IPv4 for dual-stack")
		return nil
	}

	// Allocate IPv6
	staticIPv6 := selection.PDUAddressIPv6
	if staticIPv6 == nil && selection.PDUAddress != nil && selection.PDUAddress.To4() == nil {
		staticIPv6 = selection.PDUAddress
	}

	sortedIPv6Pools := createPoolListForSelection(ipv6Pools)
	for _, pool := range sortedIPv6Pools {
		addr := pool.Allocate(staticIPv6)
		if addr != nil {
			ipv6Addr = addr
			logger.CtxLog.Debugf("WNC: ULCL allocated IPv6: %s", addr)
			break
		}
	}

	if ipv6Addr == nil {
		// Release IPv4 and fail dual-stack attempt
		logger.CtxLog.Warnf("WNC: ULCL failed to allocate IPv6 for dual-stack, releasing IPv4 %s", ipv4Addr)
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

// tryULCLSingleFamilyAllocation attempts single-family allocation for ULCL
// WNC: ULCL-specific single-family allocation using getUEIPPool
func tryULCLSingleFamilyAllocation(upi *UserPlaneInformation, upf *UPNode, selection *UPFSelectionParams, isIPv4 bool) *UEIPAllocationResult {
	// Get pools for the requested family
	var pools []*UeIPPool
	var useStatic bool
	var requestedAddr net.IP

	if isIPv4 {
		// IPv4 allocation
		ipv4Pools, _, useStaticIPv4, _ := getUEIPPoolDualStack(upf, selection)
		pools = ipv4Pools
		useStatic = useStaticIPv4
		requestedAddr = selection.PDUAddress
		if requestedAddr != nil && requestedAddr.To4() == nil {
			requestedAddr = nil // Not IPv4
		}
	} else {
		// IPv6 allocation
		_, ipv6Pools, _, useStaticIPv6 := getUEIPPoolDualStack(upf, selection)
		pools = ipv6Pools
		useStatic = useStaticIPv6
		requestedAddr = selection.PDUAddressIPv6
		if requestedAddr == nil && selection.PDUAddress != nil && selection.PDUAddress.To4() == nil {
			requestedAddr = selection.PDUAddress
		}
	}

	if len(pools) == 0 {
		return nil
	}

	sortedPools := createPoolListForSelection(pools)
	for _, pool := range sortedPools {
		addr := pool.Allocate(requestedAddr)
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

	return nil
}

// getUEIPPoolDualStack returns separate IPv4 and IPv6 pools for dual-stack ULCL allocation
// WNC: Helper to extract both families from getUEIPPool results
func getUEIPPoolDualStack(upNode *UPNode, selection *UPFSelectionParams) (ipv4Pools, ipv6Pools []*UeIPPool, useStaticIPv4, useStaticIPv6 bool) {
	// Temporarily modify selection to get IPv4 pools
	origSessionType := selection.SelectedPDUSessionType
	
	// Get IPv4 pools
	selection.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4
	ipv4Pools, useStaticIPv4 = getUEIPPool(upNode, selection)
	
	// Get IPv6 pools
	selection.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv6
	ipv6Pools, useStaticIPv6 = getUEIPPool(upNode, selection)
	
	// Restore original session type
	selection.SelectedPDUSessionType = origSessionType
	
	return ipv4Pools, ipv6Pools, useStaticIPv4, useStaticIPv6
}
