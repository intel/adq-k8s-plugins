package netlinktc

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

type Direction string

const (
	DirectionLocal  Direction = "dst"
	DirectionRemote Direction = "src"
)

const (
	handleSharedClassID        = uint32(0xFFFF0000)
	ProtocolALLstr      string = "all"
	ProtocolTCPstr      string = "tcp"
	ProtocolUDPstr      string = "udp"
	ProtocolSCTPstr     string = "sctp"

	PortsALL    int32  = 0
	PortsALLstr string = "all"
)

type NetlinkTcObject struct {
	link        netlink.Link
	mqprioQdisc *netlink.MqPrio
}

type NetlinkTc interface {
	GetNumTC() uint8
	GetSharedTC() (uint8, error)
	TCGetStartStopQ(tc uint8) (uint16, uint16, error)
	TCAddFilter(createFilterFunc FilterGenerator, filter AdqFilter) error
	TCDelFlowerFilters(ip net.IP) ([]*netlink.Flower, error)
	TCGetFlowerFilters() ([]*netlink.Flower, error)
	TCDelMatchingU32Filters([]*netlink.Flower) error
}

var (
	netlinkLinkByName = netlink.LinkByName
	netlinkQdiscList  = netlink.QdiscList
	netlinkFilterAdd  = netlink.FilterAdd
	netlinkFilterList = netlink.FilterList
	netlinkFilterDel  = netlink.FilterDel
)

func StringToIpProto(ipProto string) uint8 {
	switch strings.ToLower(ipProto) {
	case "tcp":
		return unix.IPPROTO_TCP
	case "udp":
		return unix.IPPROTO_UDP
	case "sctp":
		return unix.IPPROTO_SCTP
	}
	return uint8(0)
}

func GetHWClassID(tcVal uint32) (uint32, error) {
	//https://patchwork.ozlabs.org/project/netdev/patch/150969924183.26117.13696607595033656049.stgit@anamdev.jf.intel.com/
	if tcVal > 15 {
		return 15, fmt.Errorf("provided hw_tc:%v exceeds max 0x000F", tcVal)
	}
	hwtc := tcVal + netlink.HANDLE_MIN_INGRESS
	return hwtc, nil
}

func Init(ifname string, virtual bool) (NetlinkTc, error) {
	link, err := netlinkLinkByName(ifname)
	if err != nil {
		return nil, err
	}
	qdisc, err := netlinkQdiscList(link)
	if err != nil {
		return nil, err
	}
	rv := &NetlinkTcObject{link: link}

	if virtual {
		return rv, nil
	}

	for _, q := range qdisc {
		mqprio, ok := q.(*netlink.MqPrio)
		if !ok {
			continue
		}
		rv.mqprioQdisc = mqprio
		return rv, nil
	}

	return nil, fmt.Errorf("mqprio qdisc not found for the interface:%s", ifname)
}

// GetNumTC returns number of TCs enabled on the mqprio qdisc
func (tc *NetlinkTcObject) GetNumTC() uint8 {
	if tc.mqprioQdisc == nil {
		return 0
	}
	return tc.mqprioQdisc.Opt.NumTc
}

// GetSharedTC picks the TC used to allocate single queue ADQs
// Currently its the last one in the PrioTcMap
func (tc *NetlinkTcObject) GetSharedTC() (uint8, error) {
	if tc.mqprioQdisc == nil {
		return 0, fmt.Errorf("mqprioQdisc is nil")
	}

	if tc.mqprioQdisc.Opt.NumTc < 1 {
		return 0, errors.New("need at least one TC to be allocated, found none")
	}
	return tc.mqprioQdisc.Opt.NumTc - 1, nil
}

// TCGetStartStopQ returns the start and stop queues of a given tc
func (tc *NetlinkTcObject) TCGetStartStopQ(tcNum uint8) (uint16, uint16, error) {
	if tc.mqprioQdisc == nil {
		return 0, 0, fmt.Errorf("mqprioQdisc is nil")
	}

	opt := tc.mqprioQdisc.Opt
	if tcNum >= opt.NumTc {
		return 0, 0, fmt.Errorf("requested tc %v is not provisioned, max: %v", tcNum, opt.NumTc-1)
	}
	startQ := opt.Offset[tcNum]
	stopQ := opt.Offset[tcNum] + opt.Count[tcNum] - 1
	return startQ, stopQ, nil
}

func GetPort(protoNum, protoNumField uint8, direction, directionField Direction, portValue uint16) uint16 {
	if (protoNum == protoNumField) && (direction == directionField) {
		return portValue
	}
	return 0
}

type TunnelMode uint32

const (
	TUNNELING_DISABLED TunnelMode = 0
	TUNNELING_VXLAN    TunnelMode = 1
)

type AdqFilter struct {
	IpAddress   net.IP
	Tunnel      TunnelMode
	IpProto     uint8
	TC          uint32
	QueueNumber uint16
	Dir         Direction
	PortValue   uint16
	FilterPrio  uint16
}

type FilterGenerator func(int, AdqFilter) (netlink.Filter, error)

func (tc *NetlinkTcObject) TCAddFilter(createFilterFunc FilterGenerator, filter AdqFilter) error {
	logger := logrus.WithField("func", "AddFilter").WithField("pkg", "netlinktc")

	f, err := createFilterFunc(tc.link.Attrs().Index, filter)
	if err != nil {
		return err
	}
	if err := netlinkFilterAdd(f); err != nil {
		logger.WithError(err).Error("Failed to setup ingress filter")
		return err
	}
	return nil
}

func CreateIngressFlower(linkIndex int, filter AdqFilter) (netlink.Filter, error) {
	var handle uint32
	logger := logrus.WithField("func", "CreateIngress").WithField("pkg", "netlinktc")

	if filter.QueueNumber != 0 { // adq-shared
		maj, min := netlink.MajorMinor(uint32(filter.QueueNumber) + uint32(1) + handleSharedClassID)
		handle = netlink.MakeHandle(maj, min)
	} else { // adq
		if filter.TC > 15 {
			return nil, fmt.Errorf("provided TC:%v exceeds max 0x000F", filter.TC)
		}
		maj, min := netlink.MajorMinor(netlink.HANDLE_MIN_PRIORITY + filter.TC)
		handle = netlink.MakeHandle(maj, min)
	}

	flags := uint32(0)
	if filter.Tunnel == TUNNELING_DISABLED {
		flags |= nl.TCA_CLS_FLAGS_SKIP_SW
	}

	ingress := &netlink.Flower{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: linkIndex,
			Parent:    netlink.HANDLE_INGRESS + 1,
			Priority:  filter.FilterPrio,
			Protocol:  unix.ETH_P_IP,
			Handle:    0,
		},
		EthType:      unix.ETH_P_IP,
		IPProto:      filter.IpProto,
		DestIP:       filter.IpAddress,
		TcpDestPort:  GetPort(filter.IpProto, unix.IPPROTO_TCP, filter.Dir, DirectionLocal, filter.PortValue),
		TcpSrcPort:   GetPort(filter.IpProto, unix.IPPROTO_TCP, filter.Dir, DirectionRemote, filter.PortValue),
		UdpDestPort:  GetPort(filter.IpProto, unix.IPPROTO_UDP, filter.Dir, DirectionLocal, filter.PortValue),
		UdpSrcPort:   GetPort(filter.IpProto, unix.IPPROTO_UDP, filter.Dir, DirectionRemote, filter.PortValue),
		SctpDestPort: GetPort(filter.IpProto, unix.IPPROTO_SCTP, filter.Dir, DirectionLocal, filter.PortValue),
		SctpSrcPort:  GetPort(filter.IpProto, unix.IPPROTO_SCTP, filter.Dir, DirectionRemote, filter.PortValue),
		Flags:        flags,
		ClassID:      handle,
	}
	logger.Infof("Created filter %+v tcp dst port %v tcp src port %v, udp src port %v udp dest port %v class id 0x%x ip %v ipproto %v ethtype %v, flags 0x%x",
		ingress,
		ingress.TcpDestPort,
		ingress.TcpSrcPort,
		ingress.UdpSrcPort,
		ingress.UdpDestPort,
		ingress.ClassID,
		ingress.DestIP,
		ingress.IPProto,
		ingress.EthType,
		ingress.Flags)

	return ingress, nil
}

func uint16ptr(i uint16) *uint16 {
	return &i
}

func CreateEgressFlower(linkIndex int, filter AdqFilter) (netlink.Filter, error) {
	if filter.TC > 15 {
		return nil, fmt.Errorf("provided hw_tc:%v exceeds max 0x000F", filter.TC)
	}

	egress := &netlink.Flower{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: linkIndex,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Priority:  filter.FilterPrio,
			Protocol:  unix.ETH_P_IP,
			Handle:    0,
		},
		EthType:      unix.ETH_P_IP,
		IPProto:      filter.IpProto,
		SrcIP:        filter.IpAddress,
		TcpDestPort:  GetPort(filter.IpProto, unix.IPPROTO_TCP, filter.Dir, DirectionRemote, filter.PortValue),
		TcpSrcPort:   GetPort(filter.IpProto, unix.IPPROTO_TCP, filter.Dir, DirectionLocal, filter.PortValue),
		UdpDestPort:  GetPort(filter.IpProto, unix.IPPROTO_UDP, filter.Dir, DirectionRemote, filter.PortValue),
		UdpSrcPort:   GetPort(filter.IpProto, unix.IPPROTO_UDP, filter.Dir, DirectionLocal, filter.PortValue),
		SctpDestPort: GetPort(filter.IpProto, unix.IPPROTO_SCTP, filter.Dir, DirectionRemote, filter.PortValue),
		SctpSrcPort:  GetPort(filter.IpProto, unix.IPPROTO_SCTP, filter.Dir, DirectionLocal, filter.PortValue),

		Actions: []netlink.Action{},
	}

	if filter.QueueNumber != 0 { // adq-shared
		if filter.Tunnel == TUNNELING_DISABLED {
			skbeditPrio := netlink.NewSkbEditAction()
			skbeditPrio.Priority = &filter.TC
			egress.Actions = append(egress.Actions, skbeditPrio)

			skbeditQueue := netlink.NewSkbEditAction()
			skbeditQueue.QueueMapping = uint16ptr(filter.QueueNumber + 1)
			egress.Actions = append(egress.Actions, skbeditQueue)
		} else if filter.Tunnel == TUNNELING_VXLAN {
			skbeditMark := netlink.NewSkbEditAction()
			skbeditMark.Mark = &filter.TC
			egress.Actions = append(egress.Actions, skbeditMark)
		}
	} else { // adq
		skbeditPrio := netlink.NewSkbEditAction()
		skbeditPrio.Priority = &filter.TC
		egress.Actions = append(egress.Actions, skbeditPrio)
	}

	return egress, nil
}

func CreateEgressU32(linkIndex int, filter AdqFilter) (netlink.Filter, error) {
	if filter.TC > 15 {
		return nil, fmt.Errorf("provided hw_tc:%v exceeds max 0x000F", filter.TC)
	}

	egress := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: linkIndex,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Priority:  filter.FilterPrio,
			Protocol:  unix.ETH_P_IP,
			Handle:    0,
		},

		Sel: &netlink.TcU32Sel{
			Keys:  nil,
			Flags: netlink.TC_U32_TERMINAL,
		},

		Mark: &nl.TcU32Mark{
			Val:  filter.TC,
			Mask: 0xFF,
		},

		Actions: []netlink.Action{},
	}

	skbeditPrio := netlink.NewSkbEditAction()
	skbeditPrio.Priority = &filter.TC
	egress.Actions = append(egress.Actions, skbeditPrio)

	skbeditQueue := netlink.NewSkbEditAction()
	skbeditQueue.QueueMapping = uint16ptr(filter.QueueNumber + 1)
	egress.Actions = append(egress.Actions, skbeditQueue)

	return egress, nil
}

func (tc *NetlinkTcObject) TCDelFlowerFilters(ip net.IP) ([]*netlink.Flower, error) {
	logger := logrus.WithField("func", "TCDelFlowerFilters").WithField("pkg", "netlinktc")
	filters, err := tc.TCGetFlowerFilters()
	if err != nil {
		return nil, err
	}

	removed := []*netlink.Flower{}

	for _, flower := range filters {
		if flower.DestIP.Equal(ip) || flower.SrcIP.Equal(ip) {
			if err := netlinkFilterDel(flower); err != nil {
				// return error or try to delete rest of the filters?
				logger.WithError(err).Errorf("Unable to delete filter for interface: %v handle: %v", tc.link.Attrs().Name, flower.Handle)
			} else {
				removed = append(removed, flower)
			}
		}
	}

	return removed, nil
}

func (tc *NetlinkTcObject) TCGetFlowerFilters() ([]*netlink.Flower, error) {
	logger := logrus.WithField("func", "TCGetFlowerFilters").WithField("pkg", "netlinktc")
	var rv []*netlink.Flower
	filters, err := netlinkFilterList(tc.link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return nil, err
	}
	logger.Infof("Found %d egress filters", len(filters))
	for _, filter := range filters {
		flower, ok := filter.(*netlink.Flower)
		if !ok {
			continue
		}

		if len(flower.Actions) > 0 {
			_, ok := flower.Actions[0].(*netlink.SkbEditAction)
			if !ok {
				continue
			}
			rv = append(rv, flower)
		}
	}
	filters, err = netlinkFilterList(tc.link, netlink.HANDLE_INGRESS+1)
	if err != nil {
		return nil, err
	}
	logger.Infof("Found %d ingress filters", len(filters))
	for _, filter := range filters {
		flower, ok := filter.(*netlink.Flower)
		if !ok {
			continue
		}
		if flower.ClassID != 0 {
			rv = append(rv, flower)
		}
	}
	return rv, nil
}

func (tc *NetlinkTcObject) TCGetU32Filters() ([]*netlink.U32, error) {
	logger := logrus.WithField("func", "TCGetU32Filters").WithField("pkg", "netlinktc")
	var rv []*netlink.U32
	filters, err := netlinkFilterList(tc.link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return nil, err
	}
	logger.Infof("Found %d egress filters", len(filters))
	for _, filter := range filters {
		fu32, ok := filter.(*netlink.U32)
		if !ok {
			continue
		}

		if len(fu32.Actions) > 0 {
			_, ok := fu32.Actions[0].(*netlink.SkbEditAction)
			if !ok {
				continue
			}
			rv = append(rv, fu32)
		}
	}

	return rv, nil
}

func (tc *NetlinkTcObject) TCDelMatchingU32Filters(flower []*netlink.Flower) error {
	logger := logrus.WithField("func", "TCDelMatchingU32Filters").WithField("pkg", "netlinktc")

	fu32, err := tc.TCGetU32Filters()
	if err != nil {
		return err
	}

	// for each flower filter check if there is U32 one and remove if queue number matches
	for _, f := range flower {
		if f.ClassID > handleSharedClassID && f.ClassID < netlink.HANDLE_MIN_PRIORITY {
			queue := f.ClassID - handleSharedClassID
			for _, u := range fu32 {
				for _, skb := range u.Actions {
					s, ok := skb.(*netlink.SkbEditAction)
					if !ok {
						continue
					}
					if s.QueueMapping != nil && *s.QueueMapping == uint16(queue) {
						if err := netlinkFilterDel(u); err != nil {
							logger.WithError(err).Errorf("Unable to delete filter for interface: %v handle: %v", tc.link.Attrs().Name, u.Handle)
							break
						}
					}
				}
			}
		}
	}
	return nil
}
