// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

type NetConf struct {
	types.NetConf
	IPMasq                   bool              `json:"ipMasq"`
	MTU                      int               `json:"mtu"`
	HostNetNS                string            `json:"host_netns"`
	RouteSourceInterfaceIPv4 string            `json:"route_source_interface_ipv4"`
	RouteSourceInterfaceIPv6 string            `json:"route_source_interface_ipv6"`
	SysCtl                   map[string]string `json:"sysctl"`
}

func setupContainerVeth(netns ns.NetNS, ifName string, mtu int, routeSrcIntfIPv4 string, routeSrcIntfIPv6 string, pr *current.Result) (*current.Interface, *current.Interface, error) {
	// The IPAM result will be something like IP=192.168.3.5/24, GW=192.168.3.1.
	// What we want is really a point-to-point link but veth does not support IFF_POINTTOPOINT.
	// Next best thing would be to let it ARP but set interface to 192.168.3.5/32 and
	// add a route like "192.168.3.0/24 via 192.168.3.1 dev $ifName".
	// Unfortunately that won't work as the GW will be outside the interface's subnet.

	// Our solution is to configure the interface with 192.168.3.5/24, then delete the
	// "192.168.3.0/24 dev $ifName" route that was automatically added. Then we add
	// "192.168.3.1/32 dev $ifName" and "192.168.3.0/24 via 192.168.3.1 dev $ifName".
	// In other words we force all traffic to ARP via the gateway except for GW itself.

	hostInterface := &current.Interface{}
	containerInterface := &current.Interface{}

	err := netns.Do(func(hostNS ns.NetNS) error {
		hostVeth, contVeth0, err := ip.SetupVeth(ifName, mtu, "", hostNS)
		if err != nil {
			return err
		}
		hostInterface.Name = hostVeth.Name
		hostInterface.Mac = hostVeth.HardwareAddr.String()
		containerInterface.Name = contVeth0.Name
		containerInterface.Mac = contVeth0.HardwareAddr.String()
		containerInterface.Sandbox = netns.Path()

		for _, ipc := range pr.IPs {
			// All addresses apply to the container veth interface
			ipc.Interface = current.Int(1)
		}

		pr.Interfaces = []*current.Interface{hostInterface, containerInterface}

		contVeth, err := net.InterfaceByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to look up %q: %v", ifName, err)
		}

		if err = ipam.ConfigureIface(ifName, pr); err != nil {
			return err
		}

		var srcIPv4, srcIPv6 net.IP
		if routeSrcIntfIPv4 != "" {
			srcIPv4, err = getIntfIP(routeSrcIntfIPv4, netlink.FAMILY_V4)
			if err != nil {
				return err
			}
		}
		if routeSrcIntfIPv6 != "" {
			srcIPv6, err = getIntfIP(routeSrcIntfIPv6, netlink.FAMILY_V6)
			if err != nil {
				return err
			}
		}

		for _, ipc := range pr.IPs {
			// Delete the route that was automatically added
			route := netlink.Route{
				LinkIndex: contVeth.Index,
				Dst: &net.IPNet{
					IP:   ipc.Address.IP.Mask(ipc.Address.Mask),
					Mask: ipc.Address.Mask,
				},
				Scope: netlink.SCOPE_NOWHERE,
			}

			if err := netlink.RouteDel(&route); err != nil {
				return fmt.Errorf("failed to delete route %v: %v", route, err)
			}

			addrBits := 32
			if ipc.Address.IP.To4() == nil {
				addrBits = 128
			}

			for _, r := range []netlink.Route{
				{
					LinkIndex: contVeth.Index,
					Dst: &net.IPNet{
						IP:   ipc.Gateway,
						Mask: net.CIDRMask(addrBits, addrBits),
					},
					Scope: netlink.SCOPE_LINK,
					Src:   ipc.Address.IP,
				},
				{
					LinkIndex: contVeth.Index,
					Dst: &net.IPNet{
						IP:   ipc.Address.IP.Mask(ipc.Address.Mask),
						Mask: ipc.Address.Mask,
					},
					Scope: netlink.SCOPE_UNIVERSE,
					Gw:    ipc.Gateway,
					Src:   ipc.Address.IP,
				},
			} {
				if err := netlink.RouteAdd(&r); err != nil {
					return fmt.Errorf("failed to add route %v: %v", r, err)
				}
			}
		}

		if srcIPv4 != nil {
			if err := replaceRouteSrcIP(contVeth.Index, srcIPv4, pr.Routes); err != nil {
				return err
			}
		}

		if srcIPv6 != nil {
			if err := replaceRouteSrcIP(contVeth.Index, srcIPv6, pr.Routes); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return nil, nil, err
	}
	return hostInterface, containerInterface, nil
}

func removeLinkLocalAddresses(addrList []netlink.Addr) []netlink.Addr {
	var res []netlink.Addr
	for _, addr := range addrList {
		// we removed link-local addresses
		if addr.Scope != int(netlink.SCOPE_UNIVERSE) {
			continue
		}
		res = append(res, addr)
	}
	return res
}

// getIntfIP returns the primary IP configured on the ifName interface for the given family.
func getIntfIP(ifName string, family int) (net.IP, error) {
	sourceIntf, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	addrList, err := netlink.AddrList(sourceIntf, family)
	addrList = removeLinkLocalAddresses(addrList)
	if err != nil {
		return nil, fmt.Errorf("cannot obtain list of IP addresses for %s: %v", sourceIntf.Attrs().Name, err)
	}
	if len(addrList) != 1 {
		return nil, fmt.Errorf("no address or more than one address configured on interface %s", sourceIntf.Attrs().Name)
	}

	return addrList[0].IP, nil
}

// replaceRouteSrcIP replaces the source IP used for the routes attached to a link.
func replaceRouteSrcIP(linkIndex int, srcIP net.IP, routes []*types.Route) error {
	family := netlink.FAMILY_V4
	isV4 := srcIP.To4() != nil
	if !isV4 {
		family = netlink.FAMILY_V6
	}
	for _, r := range routes {
		if (r.Dst.IP.To4() != nil) != isV4 {
			continue
		}
		filter := &netlink.Route{
			LinkIndex: linkIndex,
			Dst:       &r.Dst,
		}
		if r.Dst.String() == "0.0.0.0/0" || r.Dst.String() == "::/0" {
			filter.Dst = nil
		}
		routeList, err := netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_DST)
		if err != nil {
			return fmt.Errorf("cannot obtain list of routes for link index %d: %v", linkIndex, err)
		}
		if len(routeList) > 1 {
			return fmt.Errorf("%d routes found for %s", len(routeList), r.Dst.String())
		} else if len(routeList) == 0 {
			return fmt.Errorf("no route found for %s", r.Dst.String())
		}
		newRoute := routeList[0]
		newRoute.Src = srcIP
		if err := netlink.RouteReplace(&newRoute); err != nil {
			return fmt.Errorf("failed to replace route: %v", err)
		}
	}
	return nil
}

// setupHostVeth configure the veth interface on the host side, optionally moving it
// to a different netns than the one used to invoke the script.
func setupHostVeth(netns string, vethName string, result *current.Result) error {
	// vethName moved to another namespace and may have a new ifindex
	veth, err := netlink.LinkByName(vethName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", vethName, err)
	}

	var destNetns ns.NetNS
	// move hostVeth in the target NetNS
	if netns != "" {
		destNetns, err = ns.GetNS(fmt.Sprintf("/var/run/netns/%s", netns))
		if err != nil {
			return fmt.Errorf("failed to get netns %s", netns)
		}
		defer destNetns.Close()
		if err := netlink.LinkSetNsFd(veth, int(destNetns.Fd())); err != nil {
			return fmt.Errorf("failed to move host veth to target netns %s: %v", netns, err)
		}
		err = destNetns.Do(func(hostNS ns.NetNS) error {
			return netlink.LinkSetUp(veth)
		})
		if err != nil {
			return fmt.Errorf("failed to set up veth in target netns %s: %v", netns, err)
		}
	} else {
		destNetns, err = ns.GetCurrentNS()
		if err != nil {
			return fmt.Errorf("failed to get current netns")
		}
		defer destNetns.Close()
	}

	return destNetns.Do(func(hostNS ns.NetNS) error {
		for _, ipc := range result.IPs {
			maskLen := 128
			if ipc.Address.IP.To4() != nil {
				maskLen = 32
			}

			ipn := &net.IPNet{
				IP:   ipc.Gateway,
				Mask: net.CIDRMask(maskLen, maskLen),
			}
			addr := &netlink.Addr{IPNet: ipn, Label: ""}
			if err = netlink.AddrAdd(veth, addr); err != nil {
				return fmt.Errorf("failed to add IP addr (%#v) to veth: %v", ipn, err)
			}

			ipn = &net.IPNet{
				IP:   ipc.Address.IP,
				Mask: net.CIDRMask(maskLen, maskLen),
			}
			// dst happens to be the same as IP/net of host veth
			if err = ip.AddHostRoute(ipn, nil, veth); err != nil && !os.IsExist(err) {
				return fmt.Errorf("failed to add route on host: %v", err)
			}
		}

		return nil
	})
}

func cmdAdd(args *skel.CmdArgs) error {
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	// run the IPAM plugin and get back the config to apply
	r, err := ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}

	// Invoke ipam del if err to avoid ip leak
	defer func() {
		if err != nil {
			ipam.ExecDel(conf.IPAM.Type, args.StdinData)
		}
	}()

	// Convert whatever the IPAM result was into the current Result type
	result, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}

	if len(result.IPs) == 0 {
		return errors.New("IPAM plugin returned missing IP config")
	}

	if err := ip.EnableForward(result.IPs); err != nil {
		return fmt.Errorf("Could not enable IP forwarding: %v", err)
	}

	contNetns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open container netns %q: %v", args.Netns, err)
	}
	defer contNetns.Close()

	hostInterface, _, err := setupContainerVeth(
		contNetns,
		args.IfName,
		conf.MTU,
		conf.RouteSourceInterfaceIPv4,
		conf.RouteSourceInterfaceIPv6,
		result,
	)
	if err != nil {
		return err
	}

	if err = setupHostVeth(conf.HostNetNS, hostInterface.Name, result); err != nil {
		return err
	}

	if conf.IPMasq {
		chain := utils.FormatChainName(conf.Name, args.ContainerID)
		comment := utils.FormatComment(conf.Name, args.ContainerID)
		for _, ipc := range result.IPs {
			if err = ip.SetupIPMasq(&ipc.Address, chain, comment); err != nil {
				return err
			}
		}
	}

	// Only override the DNS settings in the previous result if any DNS fields
	// were provided to the ptp plugin. This allows, for example, IPAM plugins
	// to specify the DNS settings instead of the ptp plugin.
	if dnsConfSet(conf.DNS) {
		result.DNS = conf.DNS
	}

	if conf.SysCtl != nil {
		r, err := result.GetAsVersion(conf.CNIVersion)
		if err != nil {
			return fmt.Errorf("failed to get result as version %s", conf.CNIVersion)
		}
		// Result of the ptp plugin must be passed to the tuning plugin as a map
		conf.RawPrevResult, err = convertResultToMap(r)
		if err != nil {
			return fmt.Errorf("failed to convert result to map: %w", err)
		}

		confJSON, err := json.MarshalIndent(conf, "", "    ")
		if err != nil {
			return fmt.Errorf("failed to JSON encode: %w", err)
		}

		r, err = invoke.DelegateAdd(context.TODO(), "tuning", confJSON, nil)
		if err != nil {
			return fmt.Errorf("failed to invoke tuning plugin: %w", err)
		}
		// Convert the tuning result into the current Result type
		result, err = current.NewResultFromResult(r)
		if err != nil {
			return err
		}
	}

	return types.PrintResult(result, conf.CNIVersion)
}

// convertResultToMap cast the Result struct as an interface by using json.Marshal/Unmarshal
func convertResultToMap(r types.Result) (map[string]interface{}, error) {
	var prevResult map[string]interface{}
	bytes, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data %w", err)
	}
	if err = json.Unmarshal(bytes, &prevResult); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data %w", err)
	}
	return prevResult, nil
}

func dnsConfSet(dnsConf types.DNS) bool {
	return dnsConf.Nameservers != nil ||
		dnsConf.Search != nil ||
		dnsConf.Options != nil ||
		dnsConf.Domain != ""
}

func cmdDel(args *skel.CmdArgs) error {
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	if err := ipam.ExecDel(conf.IPAM.Type, args.StdinData); err != nil {
		return err
	}

	if args.Netns == "" {
		return nil
	}

	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed.
	// If the device isn't there then don't try to clean up IP masq either.
	var ipnets []*net.IPNet
	err := ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		var err error
		ipnets, err = ip.DelLinkByNameAddr(args.IfName)
		if err != nil && err == ip.ErrLinkNotFound {
			return nil
		}
		return err
	})
	if err != nil {
		//  if NetNs is passed down by the Cloud Orchestration Engine, or if it called multiple times
		// so don't return an error if the device is already removed.
		// https://github.com/kubernetes/kubernetes/issues/43014#issuecomment-287164444
		_, ok := err.(ns.NSPathNotExistErr)
		if ok {
			return nil
		}
		return err
	}

	if len(ipnets) != 0 && conf.IPMasq {
		chain := utils.FormatChainName(conf.Name, args.ContainerID)
		comment := utils.FormatComment(conf.Name, args.ContainerID)
		for _, ipn := range ipnets {
			err = ip.TeardownIPMasq(ipn, chain, comment)
		}
	}

	return err
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("ptp"))
}

func cmdCheck(args *skel.CmdArgs) error {
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	// run the IPAM plugin and get back the config to apply
	err = ipam.ExecCheck(conf.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}
	if conf.NetConf.RawPrevResult == nil {
		return fmt.Errorf("ptp: Required prevResult missing")
	}
	if err := version.ParsePrevResult(&conf.NetConf); err != nil {
		return err
	}
	// Convert whatever the IPAM result was into the current Result type
	result, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return err
	}

	var contMap, hostMap current.Interface
	// Find interfaces for name whe know, that of host-device inside container
	for _, intf := range result.Interfaces {
		if args.IfName == intf.Name {
			if args.Netns == intf.Sandbox {
				contMap = *intf
				continue
			}
		}
		// we assume the other interface corresponds to the host's interface
		hostMap = *intf
	}

	// The namespace must be the same as what was configured
	if args.Netns != contMap.Sandbox {
		return fmt.Errorf("Sandbox in prevResult %s doesn't match configured netns: %s",
			contMap.Sandbox, args.Netns)
	}

	if conf.HostNetNS != "" {
		hostNetns, err := ns.GetNS(fmt.Sprintf("/var/run/netns/%s", conf.HostNetNS))
		if err != nil {
			return fmt.Errorf("failed to open netns %q: %v", conf.HostNetNS, err)
		}
		defer hostNetns.Close()
		if err := hostNetns.Do(func(_ ns.NetNS) error {
			err := validateCniHostInterface(hostMap)
			if err != nil {
				return err
			}
			return nil
		}); err != nil {
			return err
		}
	}

	//
	// Check prevResults for ips, routes and dns against values found in the container
	if err := netns.Do(func(_ ns.NetNS) error {
		// Check interface against values found in the container
		err := validateCniContainerInterface(contMap)
		if err != nil {
			return err
		}

		err = ip.ValidateExpectedInterfaceIPs(args.IfName, result.IPs)
		if err != nil {
			return err
		}

		err = ip.ValidateExpectedRoute(result.Routes)
		if err != nil {
			return err
		}

		if conf.RouteSourceInterfaceIPv4 != "" {
			err = validateSourceIPRoute(conf.RouteSourceInterfaceIPv4, netlink.FAMILY_V4, result.Routes)
			if err != nil {
				return err
			}
		}

		if conf.RouteSourceInterfaceIPv6 != "" {
			err = validateSourceIPRoute(conf.RouteSourceInterfaceIPv6, netlink.FAMILY_V6, result.Routes)
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func validateCniContainerInterface(intf current.Interface) error {
	var link netlink.Link
	var err error

	if intf.Name == "" {
		return fmt.Errorf("Container interface name missing in prevResult: %v", intf.Name)
	}
	link, err = netlink.LinkByName(intf.Name)
	if err != nil {
		return fmt.Errorf("ptp: Container Interface name in prevResult: %s not found", intf.Name)
	}
	if intf.Sandbox == "" {
		return fmt.Errorf("ptp: Error: Container interface %s should not be in host namespace", link.Attrs().Name)
	}

	_, isVeth := link.(*netlink.Veth)
	if !isVeth {
		return fmt.Errorf("Error: Container interface %s not of type veth/p2p", link.Attrs().Name)
	}

	if intf.Mac != "" {
		if intf.Mac != link.Attrs().HardwareAddr.String() {
			return fmt.Errorf("ptp: Interface %s Mac %s doesn't match container Mac: %s", intf.Name, intf.Mac, link.Attrs().HardwareAddr)
		}
	}

	return nil
}

func validateCniHostInterface(intf current.Interface) error {
	link, err := netlink.LinkByName(intf.Name)
	if err != nil {
		return fmt.Errorf("ptp: Host Interface name in prevResult: %s not found", intf.Name)
	}
	_, isVeth := link.(*netlink.Veth)
	if !isVeth {
		return fmt.Errorf("Error: Host interface %s not of type veth/p2p", link.Attrs().Name)
	}
	return nil
}

func validateSourceIPRoute(ifaceSrcIP string, family int, resultRoutes []*types.Route) error {
	srcIP, err := getIntfIP(ifaceSrcIP, family)
	if err != nil {
		return err
	}

	var filteredRoutes []*types.Route

	for _, route := range resultRoutes {
		if family == netlink.FAMILY_V4 && route.Dst.IP.To4() != nil || family == netlink.FAMILY_V6 && route.Dst.IP.To16() != nil {
			filteredRoutes = append(filteredRoutes, route)
		}
	}

	// Ensure that each static route has the correct source IP
	for _, route := range filteredRoutes {
		find := &netlink.Route{Dst: &route.Dst, Gw: route.GW, Src: srcIP}
		routeFilter := netlink.RT_FILTER_DST | netlink.RT_FILTER_SRC
		if route.GW != nil {
			routeFilter |= netlink.RT_FILTER_GW
		}

		switch {
		case route.Dst.IP.To4() != nil:
			family = netlink.FAMILY_V4
			// Default route needs Dst set to nil
			if route.Dst.String() == "0.0.0.0/0" {
				find = &netlink.Route{Dst: nil, Gw: route.GW, Src: srcIP}
			}
		case len(route.Dst.IP) == net.IPv6len:
			family = netlink.FAMILY_V6
			// Default route needs Dst set to nil
			if route.Dst.String() == "::/0" {
				find = &netlink.Route{Dst: nil, Gw: route.GW, Src: srcIP}
			}
		default:
			return fmt.Errorf("Invalid static route found %v", route)
		}

		wasFound, err := netlink.RouteListFiltered(family, find, routeFilter)
		if err != nil {
			return fmt.Errorf("Expected Route %v not route table lookup error %v", route, err)
		}
		if wasFound == nil {
			return fmt.Errorf("Expected Route %v not found in routing table", route)
		}
	}

	return nil
}
