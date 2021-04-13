// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation

package plugin

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"

	"github.com/intel/adq-device-plugin/pkg/kubeletclient"
	"github.com/intel/adq-device-plugin/pkg/netlinktc"
	"github.com/intel/adq-device-plugin/pkg/nodeconfigtypes"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type adqConf struct {
	types.NetConf

	// Internal
	Master             string                        `json:"-"`
	TcInfo             []*kubeletclient.ResourceInfo `json:"-"`
	Tunneling          string                        `json:"tunneling,omitempty"`
	TunnelingIntefrace string                        `json:"tunneling-interface,omitempty"`

	KubeletServerName string `json:"kubeletServerName,omitempty"`
	KubeletPort       string `json:"kubeletPort,omitempty"`
	KubeletCAPath     string `json:"kubeletCAPath,omitempty"`
}

type K8sArgs struct {
	types.CommonArgs
	IP                         net.IP
	K8S_POD_NAME               types.UnmarshallableString //revive:disable-line
	K8S_POD_NAMESPACE          types.UnmarshallableString //revive:disable-line
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString //revive:disable-line
}

var (
	getKubeletClient      = kubeletclient.GetKubeletClient
	adqtcInit             = netlinktc.Init
	getContainerIP        = getContainerIPfromArgs
	linkByName            = netlink.LinkByName
	addrList              = netlink.AddrList
	withNetNSPath         = ns.WithNetNSPath
	defaultNodeConfigPath = "/etc/cni/net.d/adq-cni.d/node-config"
	egressMode            = "skbedit"
	filterPrio            = uint16(1)
)

func loadConf(bytes []byte) (*adqConf, error) {
	logger := log.WithField("func", "loadConf").WithField("pkg", "plugin")
	logger.Debugf("Bytes %s", bytes)
	n := &adqConf{}

	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("Loading network configuration unsuccessful: %v", err)
	}

	nodeConfig, err := os.ReadFile(defaultNodeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("Unable to read node config from %v, err: %v", defaultNodeConfigPath, err)
	}

	var nc nodeconfigtypes.AdqNodeConfig
	err = json.Unmarshal(nodeConfig, &nc)
	if err != nil {
		return nil, fmt.Errorf("Error when unmarshalling node-config: %v", err)
	}

	n.Master = nc.Globals.Dev
	egressMode = nc.EgressMode
	filterPrio = nc.FilterPrio

	if n.Tunneling != "disabled" && n.Tunneling != "vxlan" && n.Tunneling != "" {
		return nil, fmt.Errorf("unsupported \"tunneling\" value - can be empty or \"disabled\" or \"vxlan\"")
	}

	if n.Tunneling == "vxlan" && n.TunnelingIntefrace == "" {
		return nil, fmt.Errorf("\"tunneling-interface\" can't be empty when tunneling is enabled")
	}

	return n, nil
}

func CmdAdd(args *skel.CmdArgs) error {
	logger := log.WithField("func", "CmdAdd").WithField("pkg", "plugin")
	logger.Debugf("args %v", args.Args)

	k8sArgs := &K8sArgs{}
	err := types.LoadArgs(args.Args, k8sArgs)
	if err != nil {
		err = fmt.Errorf("Unable to load args: %v", err)
		logger.Errorf(err.Error())
		return err
	}

	n, err := loadConf(args.StdinData)
	if err != nil {
		logger.Error(err)
		return err
	}

	if n.RawPrevResult == nil {
		err = fmt.Errorf("Required prev result is missing")
		logger.Errorf(err.Error())
		return err
	}

	// Parse previous result
	if n.NetConf.RawPrevResult != nil {
		if err = version.ParsePrevResult(&n.NetConf); err != nil {
			logger.Error(err)
			return err
		}
	}

	kc, err := getKubeletClient(true, n.KubeletServerName, n.KubeletPort, n.KubeletCAPath)
	if err != nil {
		err = fmt.Errorf("Failed to get a ResourceClient instance: %v", err)
		logger.Errorf(err.Error())
		return err
	}

	result, err := current.NewResultFromResult(n.PrevResult)
	if err != nil {
		logger.Errorf(err.Error())
		return err
	}

	n.TcInfo, err = kc.GetPodResourceMap(string(k8sArgs.K8S_POD_NAME), string(k8sArgs.K8S_POD_NAMESPACE), n.Master)
	if err != nil {
		logger.Debugf("Pod: %v in namespace %v is not requesting adq", string(k8sArgs.K8S_POD_NAME), string(k8sArgs.K8S_POD_NAMESPACE))
		// how to solve this TC is required but it is possilble that we do not fetch it from kubelet
		return types.PrintResult(result, n.CNIVersion)
	}

	if len(result.IPs) == 0 {
		err = fmt.Errorf("IP address not set")
		logger.Errorf(err.Error())
		return err
	}

	if err = n.createConfiguration(kc, string(k8sArgs.K8S_POD_NAMESPACE), string(k8sArgs.K8S_POD_NAME)); err != nil {
		err = fmt.Errorf("Error in reading config from annotation %v", err)
		logger.Errorf(err.Error())
		return err
	}

	for _, c := range n.TcInfo {
		logger.Debugf("For container %s found local ports: %v \tremote ports: %v", c.ContainerName, c.LocalPorts, c.RemotePorts)
	}

	// RX
	// check mode add set mode and set TC if ther is a need

	if err := n.addTC(result.IPs[0].Address.IP); err != nil {
		return err
	}

	// Log list of filters
	n.printFilters()

	return types.PrintResult(result, n.CNIVersion)
}

func (n *adqConf) delTC(ip net.IP) error {
	logger := log.WithField("func", "delTC").WithField("pkg", "plugin")

	object, err := adqtcInit(n.Master, false)
	if err != nil {
		logger.Errorf("Failed to init adqtc")
		return err
	}

	if n.Tunneling == "vxlan" {
		vObject, err := adqtcInit(n.TunnelingIntefrace, true)
		if err != nil {
			logger.Errorf("Failed to init netlinktc for %s", n.TunnelingIntefrace)
			return err
		}

		removed, err := vObject.TCDelFlowerFilters(ip)
		if err != nil {
			logger.Errorf("Failed to delete flower filters for interface: %v", n.TunnelingIntefrace)
			return err
		}

		err = object.TCDelMatchingU32Filters(removed)
		if err != nil {
			logger.Errorf("Failed to delete matching U32 filters for interface: %v", n.Master)
			return err
		}
	} else {
		_, err = object.TCDelFlowerFilters(ip)
		if err != nil {
			logger.Errorf("Failed to delete filters for interface: %v", n.Master)
			return err
		}
	}

	return nil
}

func (n *adqConf) addTC(ip net.IP) error {
	logger := log.WithField("func", "addTC").WithField("pkg", "plugin")
	object, err := adqtcInit(n.Master, false)
	if err != nil {
		logger.Errorf("Failed to init adqtc")
		return err
	}

	var vObject netlinktc.NetlinkTc
	if n.Tunneling == "vxlan" {
		vObject, err = adqtcInit(n.TunnelingIntefrace, true)
		if err != nil {
			logger.Errorf("Failed to init adqtc for %s", n.TunnelingIntefrace)
			return err
		}
	}

	for _, i := range n.TcInfo {
		tc, err := strconv.ParseUint(i.TC, 10, 32)
		if err != nil {
			logger.Errorf("Invalid TC value %v ...skipping", i.TC)
			continue
		}

		var queue uint64
		if i.SingleQueueNumber != "" {
			queue, err = strconv.ParseUint(i.SingleQueueNumber, 10, 32)
			if err != nil {
				logger.Errorf("Invalid Queue value %v ...skipping", i.SingleQueueNumber)
				continue
			}
		}

		f := netlinktc.AdqFilter{
			IpAddress:   ip,
			TC:          uint32(tc),
			QueueNumber: uint16(queue),
			FilterPrio:  filterPrio,
		}

		if n.Tunneling == "vxlan" {
			f.Tunnel = netlinktc.TUNNELING_VXLAN
			for _, p := range append(i.LocalPorts, i.RemotePorts...) {
				f.IpProto = netlinktc.StringToIpProto(p.Protocol)
				f.Dir = p.Direction
				f.PortValue = uint16(p.ContainerPort)

				err := vObject.TCAddFilter(netlinktc.CreateIngressFlower, f)
				if err != nil {
					logger.Errorf("Failed to add filter [%+v] on Interface:%s err: %v", f, n.TunnelingIntefrace, err)
					return err
				}

				f.FilterPrio = 1
				err = vObject.TCAddFilter(netlinktc.CreateEgressFlower, f)
				if err != nil {
					logger.Errorf("Failed to add filter [%+v] on Interface:%s err: %v", f, n.TunnelingIntefrace, err)
					return err
				}

				if f.QueueNumber > 0 { // additional U32 egress filter on PF for adq-shared + VXLAN
					err = object.TCAddFilter(netlinktc.CreateEgressU32, f)
					if err != nil {
						logger.Errorf("Failed to add filter [%+v] on Interface:%s err: %v", f, n.Master, err)
						return err
					}
				}
			}
		} else {
			f.Tunnel = netlinktc.TUNNELING_DISABLED
			for _, p := range append(i.LocalPorts, i.RemotePorts...) {
				f.IpProto = netlinktc.StringToIpProto(p.Protocol)
				f.Dir = p.Direction
				f.PortValue = uint16(p.ContainerPort)

				err := object.TCAddFilter(netlinktc.CreateIngressFlower, f)
				if err != nil {
					logger.Errorf("Failed to add filter [%+v] on Interface:%s err: %v", f, n.Master, err)
					return err
				}

				if egressMode == "skbedit" {
					err = object.TCAddFilter(netlinktc.CreateEgressFlower, f)
					if err != nil {
						logger.Errorf("Failed to add filter [%+v] on Interface:%s err: %v", f, n.Master, err)
						return err
					}
				}
			}
		}
	}

	return nil
}

func CmdCheck(args *skel.CmdArgs) error {
	logger := log.WithField("func", "CmdCheck").WithField("pkg", "plugin")
	k8sArgs := &K8sArgs{
		CommonArgs:                 types.CommonArgs{},
		IP:                         []byte{},
		K8S_POD_NAME:               "",
		K8S_POD_NAMESPACE:          "",
		K8S_POD_INFRA_CONTAINER_ID: "",
	}

	err := types.LoadArgs(args.Args, k8sArgs)
	if err != nil {
		return err
	}

	n, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	// CHECK was added in CNI spec version 0.4.0 and higher
	if res, err := version.GreaterThanOrEqualTo(n.CNIVersion, "0.4.0"); err != nil {
		return err
	} else if !res {
		return fmt.Errorf("Configuration version %q does not support the CHECK command", n.CNIVersion)
	}

	// Parse previous result.
	if n.NetConf.RawPrevResult == nil {
		return fmt.Errorf("Required prevResult missing")
	}

	if err := version.ParsePrevResult(&n.NetConf); err != nil {
		return err
	}

	result, err := current.NewResultFromResult(n.PrevResult)
	if err != nil {
		return err
	}

	if len(result.IPs) == 0 {
		return fmt.Errorf("Required ip address not set")
	}

	kc, err := getKubeletClient(true, n.KubeletServerName, n.KubeletPort, n.KubeletCAPath)
	if err != nil {
		return fmt.Errorf("Failed to get a ResourceClient instance err: %v", err)
	}

	n.TcInfo, err = kc.GetPodResourceMap(string(k8sArgs.K8S_POD_NAME), string(k8sArgs.K8S_POD_NAMESPACE), n.Master)
	if err != nil {
		// pod does not require adq
		return nil
	}

	if err = n.createConfiguration(kc, string(k8sArgs.K8S_POD_NAMESPACE), string(k8sArgs.K8S_POD_NAME)); err != nil {
		logger.Errorf("Error in reading config from annotation, trying legacy approach")
		return err
	}

	for _, i := range n.TcInfo {
		for _, p := range i.LocalPorts {
			err = validateTcSettings(n.Master, i.TC, result.IPs[0].Address.IP, p.Protocol, p.Direction, uint16(p.ContainerPort))
			if err != nil {
				return err
			}
		}
		for _, p := range i.RemotePorts {
			err = validateTcSettings(n.Master, i.TC, result.IPs[0].Address.IP, p.Protocol, p.Direction, uint16(p.ContainerPort))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func validateTcSettings(master string, tc string, ip net.IP, ipProto string, direction netlinktc.Direction, port uint16) error {
	logger := log.WithField("func", "validateTcSettings").WithField("pkg", "plugin")
	object, err := adqtcInit(master, false)
	if err != nil {
		logger.Errorf("Failed to init adqtc")
		return err
	}

	filters, err := object.TCGetFlowerFilters()
	if err != nil {
		logger.Errorf("Failed to get filters")
		return err
	}

	tcVal, err := strconv.ParseUint(tc, 10, 32)
	if err != nil {
		logger.Errorf("Invalid TC value %v ...skipping", tc)
		return err
	}

	hwtc, err := netlinktc.GetHWClassID(uint32(tcVal))
	if err != nil {
		logger.Errorf("Unable to get HW class ID for TC:%v", tcVal)
		return err
	}

	found := false
	for _, f := range filters {
		if f.ClassID != hwtc {
			continue
		}
		if f.FilterAttrs.Parent == netlink.HANDLE_MIN_EGRESS {
			if !f.SrcIP.Equal(ip) {
				continue
			}
		}

		if f.FilterAttrs.Parent == netlink.HANDLE_MIN_INGRESS+1 {
			if !f.DestIP.Equal(ip) {
				continue
			}
		}

		if f.IPProto != netlinktc.StringToIpProto(ipProto) {
			continue
		}

		pk := netlinktc.GetPort(netlinktc.StringToIpProto(ipProto), unix.IPPROTO_UDP, direction, netlinktc.DirectionRemote, port)
		if f.UdpSrcPort != pk {
			continue
		}

		pk = netlinktc.GetPort(netlinktc.StringToIpProto(ipProto), unix.IPPROTO_UDP, direction, netlinktc.DirectionLocal, port)
		if f.UdpDestPort != pk {
			continue
		}

		pk = netlinktc.GetPort(netlinktc.StringToIpProto(ipProto), unix.IPPROTO_TCP, direction, netlinktc.DirectionRemote, port)
		if f.TcpSrcPort != pk {
			continue
		}

		pk = netlinktc.GetPort(netlinktc.StringToIpProto(ipProto), unix.IPPROTO_TCP, direction, netlinktc.DirectionLocal, port)
		if f.TcpDestPort != pk {
			continue
		}

		pk = netlinktc.GetPort(netlinktc.StringToIpProto(ipProto), unix.IPPROTO_SCTP, direction, netlinktc.DirectionRemote, port)
		if f.SctpSrcPort != pk {
			continue
		}

		pk = netlinktc.GetPort(netlinktc.StringToIpProto(ipProto), unix.IPPROTO_SCTP, direction, netlinktc.DirectionLocal, port)
		if f.SctpDestPort != pk {
			continue
		}
		found = true
	}

	if !found {
		return fmt.Errorf("Cannot find filter on interface:%v [IP:%v port:%v direction:%v protocol:%v TC:%v]",
			master, ip.String(), port, direction, ipProto, tc)
	}

	return nil
}

func (n *adqConf) printFilters() {
	logger := log.WithField("func", "printFilters").WithField("pkg", "plugin")
	object, err := adqtcInit(n.Master, false)
	if err != nil {
		logger.Errorf("Failed to init adqtc: %v", err)
		return
	}

	filters, err := object.TCGetFlowerFilters()
	if err != nil {
		logger.Errorf("Failed to get filters: %v", err)
		return
	}

	for _, f := range filters {
		logger.Infof("%+v", f)
	}
}

func getContainerIPfromArgs(args *skel.CmdArgs) (net.IP, error) {
	logger := log.WithField("func", "getContainerIPfromArgs").WithField("pkg", "plugin")
	var ip net.IP
	err := withNetNSPath(args.Netns, func(_ ns.NetNS) error {
		link, err := linkByName(args.IfName)
		if err != nil {
			logger.Errorf("Cannot get link")
			return err
		}
		v4addr, err := addrList(link, netlink.FAMILY_V4)
		if err != nil {
			logger.Errorf("Cannot get ip address")
			return err
		}
		ip = v4addr[0].IP
		return nil
	})
	return ip, err
}

func CmdDel(args *skel.CmdArgs) error {
	logger := log.WithField("func", "CmdDel").WithField("pkg", "plugin")
	logger.Debugf("args: %v", args.Args)

	k8sArgs := &K8sArgs{}
	err := types.LoadArgs(args.Args, k8sArgs)
	if err != nil {
		err = fmt.Errorf("Unable to load args: %v", err)
		logger.Errorf(err.Error())
		return err
	}

	n, err := loadConf(args.StdinData)
	if err != nil {
		err = fmt.Errorf("Unable to load config: %v", err)
		logger.Errorf(err.Error())
		return err
	}

	// get ip
	ip, err := getContainerIP(args)
	if err != nil {
		err = fmt.Errorf("Unable to get container ip: %v", err)
		logger.Errorf(err.Error())
		return err
	}

	return n.delTC(ip)
}

func (n *adqConf) createConfiguration(kc kubeletclient.KubeletClient, namespace string, pod string) error {
	logger := log.WithField("func", "getConfiguration").WithField("pkg", "plugin")
	adqPortConfig, err := kc.GetAdqConfig(namespace, pod)
	if err != nil {
		logger.Errorf("Error when retreiving ADQ annotation")
		return err
	}
	splitPorts := func(s string, d netlinktc.Direction) *kubeletclient.Port {
		if strings.ToLower(s) == netlinktc.ProtocolALLstr {
			return &kubeletclient.Port{ContainerPort: netlinktc.PortsALL, Protocol: netlinktc.ProtocolALLstr, Direction: d}
		} else {
			ps := strings.Split(s, "/")
			if len(ps) == 2 { // PORT_VALUE/PROTOCOL
				var portNum int32 = netlinktc.PortsALL
				portStr := strings.ToLower(strings.TrimSpace(ps[0]))
				if portStr != netlinktc.PortsALLstr {
					p, err := strconv.ParseInt(portStr, 10, 32)
					if err != nil {
						logger.Errorf("Error when parsing port value: %v", err)
						return nil
					}
					portNum = int32(p)
				}
				return &kubeletclient.Port{ContainerPort: int32(portNum), Protocol: strings.TrimSpace(ps[1]), Direction: d}
			}
		}
		return nil
	}

	getConfigEntry := func(contName string,
		config []*kubeletclient.AdqConfigEntry) *kubeletclient.AdqConfigEntry {
		for _, c := range config {
			if c.Name == contName {
				return c
			}
		}
		return nil
	}

	// iterate over containers that request ADQ resource
	for _, tcInfo := range n.TcInfo {
		entry := getConfigEntry(tcInfo.ContainerName, adqPortConfig)
		if entry == nil {
			// port configuration not found - use ALL for local (dst)
			logger.Debugf("Port configuration for container %s not found - using default ALL", tcInfo.ContainerName)
			p := splitPorts(netlinktc.ProtocolALLstr, netlinktc.DirectionLocal)
			tcInfo.LocalPorts = append(tcInfo.LocalPorts, *p)
		} else {
			// port configuration found
			for _, lp := range entry.Ports.LocalPorts {
				if p := splitPorts(lp, netlinktc.DirectionLocal); p != nil {
					tcInfo.LocalPorts = append(tcInfo.LocalPorts, *p)
				}
			}

			for _, rp := range entry.Ports.RemotePorts {
				if p := splitPorts(rp, netlinktc.DirectionRemote); p != nil {
					tcInfo.RemotePorts = append(tcInfo.RemotePorts, *p)
				}
			}
		}
	}

	return nil
}
