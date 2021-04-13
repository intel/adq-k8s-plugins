// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation

package netlinktc

import (
	"errors"
	"net"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

type LinkMock struct {
	Qdiscs    []netlink.Qdisc
	LinkAttrs netlink.LinkAttrs
}

func (lm *LinkMock) Attrs() *netlink.LinkAttrs {
	return &lm.LinkAttrs
}

func (lm *LinkMock) Type() string {
	return ""
}

var (
	linkMock           LinkMock
	linkByNameError    error
	linkQdiscListError error
)

func fakeLinkByName(name string) (netlink.Link, error) {
	return &linkMock, linkByNameError
}

func fakeQdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
	return linkMock.Qdiscs, linkQdiscListError
}

func TestNetlinktc(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Netlinktc Test Suite")
}

var _ = Describe("Init should return error if", func() {
	netlinkLinkByName = fakeLinkByName
	netlinkQdiscList = fakeQdiscList
	linkMock = LinkMock{}
	linkByNameError = nil
	linkQdiscListError = nil

	var _ = It("is not able to get link by name", func() {
		linkByNameError = errors.New("link by name error")
		ntc, err := Init("someEth", false)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("link by name error"))
		Expect(ntc).To(BeNil())
	})

	var _ = It("is not able to list qdiscs", func() {
		linkByNameError = nil

		netlinkQdiscList = func(link netlink.Link) ([]netlink.Qdisc, error) {
			return nil, errors.New("qdisc list error")
		}

		ntc, err := Init("someEth", false)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("qdisc list error"))
		Expect(ntc).To(BeNil())
	})

})

var _ = Describe("TCAddFilter should return error if", func() {
	mqprio := netlink.MqPrio{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: 5,
			Handle:    1,
			Parent:    2,
		},
		Opt: nl.TcMqPrioQopt{ // queues:(0:15) (16:19) (20:23) (24:27) (28:31) (32:63)
			NumTc: 6,
			Count: [16]uint16{
				16,
				4,
				4,
				4,
				4,
				32,
			},
			Offset: [16]uint16{
				0,
				16,
				20,
				24,
				28,
				32,
			},
		},
	}
	linkMock = LinkMock{
		Qdiscs: []netlink.Qdisc{
			&mqprio,
		},
		LinkAttrs: netlink.LinkAttrs{
			Index: 5,
		},
	}

	var _ = BeforeEach(func() {
		linkByNameError = nil
		linkQdiscListError = nil
		netlinkLinkByName = fakeLinkByName
		netlinkQdiscList = func(link netlink.Link) ([]netlink.Qdisc, error) {
			return linkMock.Qdiscs, nil
		}
	})

	var _ = AfterEach(func() {
	})

	var _ = It("createFilterFunc returns error", func() {
		ntc, err := Init("someEth", false)
		Expect(err).ToNot(HaveOccurred())
		Expect(ntc).ToNot(BeNil())

		adqf := AdqFilter{
			IpAddress: net.ParseIP("10.123.123.1"),
			Tunnel:    TUNNELING_DISABLED,
			TC:        1,
		}

		fakeCreateFilterFunc := func(int, AdqFilter) (netlink.Filter, error) {
			return nil, errors.New("create filter error")
		}

		err = ntc.TCAddFilter(fakeCreateFilterFunc, adqf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("create filter error"))

	})

	var _ = It("netlink.FilterAdd returns error", func() {
		ntc, err := Init("someEth", false)
		Expect(err).ToNot(HaveOccurred())
		Expect(ntc).ToNot(BeNil())

		adqf := AdqFilter{
			IpAddress: net.ParseIP("10.123.123.1"),
			Tunnel:    TUNNELING_DISABLED,
			TC:        1,
		}

		fakeCreateFilterFunc := func(int, AdqFilter) (netlink.Filter, error) {
			return nil, nil
		}

		netlinkFilterAdd = func(filter netlink.Filter) error {
			return errors.New("netlink.FilterAdd error")
		}

		err = ntc.TCAddFilter(fakeCreateFilterFunc, adqf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("netlink.FilterAdd error"))

	})
})

var _ = Describe("TCAddFilter should not return error if", func() {
	mqprio := netlink.MqPrio{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: 5,
			Handle:    1,
			Parent:    2,
		},
		Opt: nl.TcMqPrioQopt{ // queues:(0:15) (16:19) (20:23) (24:27) (28:31) (32:63)
			NumTc: 6,
			Count: [16]uint16{
				16,
				4,
				4,
				4,
				4,
				32,
			},
			Offset: [16]uint16{
				0,
				16,
				20,
				24,
				28,
				32,
			},
		},
	}
	linkMock = LinkMock{
		Qdiscs: []netlink.Qdisc{
			&mqprio,
		},
		LinkAttrs: netlink.LinkAttrs{
			Index: 5,
		},
	}

	var _ = BeforeEach(func() {
		linkByNameError = nil
		linkQdiscListError = nil
		netlinkLinkByName = fakeLinkByName
		netlinkQdiscList = func(link netlink.Link) ([]netlink.Qdisc, error) {
			return linkMock.Qdiscs, nil
		}
	})

	var _ = AfterEach(func() {
	})

	var _ = It("passed objects are valid", func() {
		ntc, err := Init("someEth", false)
		Expect(err).ToNot(HaveOccurred())
		Expect(ntc).ToNot(BeNil())

		adqf := AdqFilter{
			IpAddress: net.ParseIP("10.123.123.1"),
			Tunnel:    TUNNELING_DISABLED,
			TC:        1,
		}

		netlinkFilterAdd = func(filter netlink.Filter) error {
			f, ok := filter.(*netlink.Flower)
			Expect(ok).To(BeTrue())
			Expect(f.DestIP).To(Equal(adqf.IpAddress))
			Expect(f.ClassID).To(Equal(netlink.HANDLE_MIN_PRIORITY + adqf.TC))
			return nil
		}

		err = ntc.TCAddFilter(CreateIngressFlower, adqf)
		Expect(err).ToNot(HaveOccurred())

	})
})

var _ = Describe("CreateIngressFlower should", func() {
	var _ = It("return error if provided TC value exceeds max", func() {
		adqf := AdqFilter{
			IpAddress: net.ParseIP("10.123.123.1"),
			Tunnel:    TUNNELING_DISABLED,
			TC:        25,
		}

		f, err := CreateIngressFlower(5, adqf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("provided TC:25 exceeds max 0x000F"))
		Expect(f).To(BeNil())

	})

	var _ = It("return valid flower filter if passed data is valid (adq)", func() {
		adqf := AdqFilter{
			IpAddress:  net.ParseIP("10.123.123.1"),
			Tunnel:     TUNNELING_DISABLED,
			TC:         3,
			IpProto:    StringToIpProto("TCP"),
			PortValue:  12345,
			Dir:        DirectionLocal,
			FilterPrio: 1,
		}

		f, err := CreateIngressFlower(5, adqf)
		Expect(err).ToNot(HaveOccurred())
		Expect(f).ToNot(BeNil())

		flower, ok := f.(*netlink.Flower)
		Expect(ok).To(BeTrue())
		Expect(flower.Attrs().LinkIndex).To(Equal(5))
		Expect(flower.Attrs().Parent).To(Equal(uint32(netlink.HANDLE_INGRESS + 1)))
		Expect(flower.Attrs().Priority).To(Equal(uint16(adqf.FilterPrio)))
		Expect(flower.Attrs().Protocol).To(Equal(uint16(unix.ETH_P_IP)))
		Expect(flower.Attrs().Handle).To(Equal(uint32(0)))

		Expect(flower.EthType).To(Equal(uint16(unix.ETH_P_IP)))
		Expect(flower.IPProto).To(Equal(adqf.IpProto))
		Expect(flower.DestIP).To(Equal(adqf.IpAddress))
		Expect(flower.TcpDestPort).To(Equal(uint16(12345)))
		Expect(flower.TcpSrcPort).To(Equal(uint16(0)))
		Expect(flower.UdpDestPort).To(Equal(uint16(0)))
		Expect(flower.UdpSrcPort).To(Equal(uint16(0)))
		Expect(flower.Flags).To(Equal(nl.TCA_CLS_FLAGS_SKIP_SW))
		Expect(flower.ClassID).To(Equal(netlink.HANDLE_MIN_PRIORITY + adqf.TC))
	})

	var _ = It("return valid flower filter if passed data is valid (adq-shared)", func() {
		adqf := AdqFilter{
			IpAddress:   net.ParseIP("10.123.123.1"),
			Tunnel:      TUNNELING_DISABLED,
			TC:          3,
			IpProto:     StringToIpProto("TCP"),
			PortValue:   12345,
			Dir:         DirectionLocal,
			QueueNumber: 128,
			FilterPrio:  1,
		}

		f, err := CreateIngressFlower(5, adqf)
		Expect(err).ToNot(HaveOccurred())
		Expect(f).ToNot(BeNil())

		flower, ok := f.(*netlink.Flower)
		Expect(ok).To(BeTrue())
		Expect(flower.Attrs().LinkIndex).To(Equal(5))
		Expect(flower.Attrs().Parent).To(Equal(uint32(netlink.HANDLE_INGRESS + 1)))
		Expect(flower.Attrs().Priority).To(Equal(uint16(adqf.FilterPrio)))
		Expect(flower.Attrs().Protocol).To(Equal(uint16(unix.ETH_P_IP)))
		Expect(flower.Attrs().Handle).To(Equal(uint32(0)))

		Expect(flower.EthType).To(Equal(uint16(unix.ETH_P_IP)))
		Expect(flower.IPProto).To(Equal(adqf.IpProto))
		Expect(flower.SrcIP).To(Equal(net.IP(nil)))
		Expect(flower.DestIP).To(Equal(adqf.IpAddress))
		Expect(flower.TcpDestPort).To(Equal(uint16(12345)))
		Expect(flower.TcpSrcPort).To(Equal(uint16(0)))
		Expect(flower.UdpDestPort).To(Equal(uint16(0)))
		Expect(flower.UdpSrcPort).To(Equal(uint16(0)))
		Expect(flower.Flags).To(Equal(nl.TCA_CLS_FLAGS_SKIP_SW))

		maj, min := netlink.MajorMinor(uint32(adqf.QueueNumber) + uint32(1) + handleSharedClassID)
		handle := netlink.MakeHandle(maj, min)
		Expect(flower.ClassID).To(Equal(handle))
	})
})

var _ = Describe("CreateEgressFlower should", func() {
	var _ = It("return error if provided TC value exceeds max", func() {
		adqf := AdqFilter{
			IpAddress: net.ParseIP("10.123.123.1"),
			Tunnel:    TUNNELING_DISABLED,
			TC:        25,
		}

		f, err := CreateEgressFlower(5, adqf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("provided hw_tc:25 exceeds max 0x000F"))
		Expect(f).To(BeNil())

	})

	var _ = It("return valid flower filter if passed data is valid (adq) TUNNELING_DISABLED", func() {
		adqf := AdqFilter{
			IpAddress:  net.ParseIP("10.123.123.1"),
			Tunnel:     TUNNELING_DISABLED,
			TC:         3,
			IpProto:    StringToIpProto("TCP"),
			PortValue:  12345,
			Dir:        DirectionLocal,
			FilterPrio: 1,
		}

		f, err := CreateEgressFlower(5, adqf)
		Expect(err).ToNot(HaveOccurred())
		Expect(f).ToNot(BeNil())

		flower, ok := f.(*netlink.Flower)
		Expect(ok).To(BeTrue())
		Expect(flower.Attrs().LinkIndex).To(Equal(5))
		Expect(flower.Attrs().Parent).To(Equal(uint32(netlink.HANDLE_MIN_EGRESS)))
		Expect(flower.Attrs().Priority).To(Equal(uint16(adqf.FilterPrio)))
		Expect(flower.Attrs().Protocol).To(Equal(uint16(unix.ETH_P_IP)))
		Expect(flower.Attrs().Handle).To(Equal(uint32(0)))

		Expect(flower.EthType).To(Equal(uint16(unix.ETH_P_IP)))
		Expect(flower.IPProto).To(Equal(adqf.IpProto))
		Expect(flower.SrcIP).To(Equal(adqf.IpAddress))
		Expect(flower.DestIP).To(Equal(net.IP(nil)))
		Expect(flower.TcpSrcPort).To(Equal(uint16(12345)))
		Expect(flower.TcpDestPort).To(Equal(uint16(0)))
		Expect(flower.UdpDestPort).To(Equal(uint16(0)))
		Expect(flower.UdpSrcPort).To(Equal(uint16(0)))

		Expect(flower.Actions).To(HaveLen(1))
		skb, ok := flower.Actions[0].(*netlink.SkbEditAction)
		Expect(ok).To(BeTrue())
		Expect(*skb.Priority).To(Equal(adqf.TC))

		Expect(skb.Mark).To(BeNil())
		Expect(skb.QueueMapping).To(BeNil())
	})

	var _ = It("return valid flower filter if passed data is valid (adq-shared) TUNNELING_DISABLED", func() {
		adqf := AdqFilter{
			IpAddress:   net.ParseIP("10.123.123.1"),
			Tunnel:      TUNNELING_DISABLED,
			TC:          3,
			IpProto:     StringToIpProto("TCP"),
			PortValue:   12345,
			Dir:         DirectionLocal,
			QueueNumber: 128,
			FilterPrio:  1,
		}

		f, err := CreateEgressFlower(5, adqf)
		Expect(err).ToNot(HaveOccurred())
		Expect(f).ToNot(BeNil())

		flower, ok := f.(*netlink.Flower)
		Expect(ok).To(BeTrue())
		Expect(flower.Attrs().LinkIndex).To(Equal(5))
		Expect(flower.Attrs().Parent).To(Equal(uint32(netlink.HANDLE_MIN_EGRESS)))
		Expect(flower.Attrs().Priority).To(Equal(uint16(adqf.FilterPrio)))
		Expect(flower.Attrs().Protocol).To(Equal(uint16(unix.ETH_P_IP)))
		Expect(flower.Attrs().Handle).To(Equal(uint32(0)))

		Expect(flower.EthType).To(Equal(uint16(unix.ETH_P_IP)))
		Expect(flower.IPProto).To(Equal(adqf.IpProto))
		Expect(flower.SrcIP).To(Equal(adqf.IpAddress))
		Expect(flower.DestIP).To(Equal(net.IP(nil)))
		Expect(flower.TcpSrcPort).To(Equal(uint16(12345)))
		Expect(flower.TcpDestPort).To(Equal(uint16(0)))
		Expect(flower.UdpDestPort).To(Equal(uint16(0)))
		Expect(flower.UdpSrcPort).To(Equal(uint16(0)))

		Expect(flower.Actions).To(HaveLen(2))
		skb, ok := flower.Actions[0].(*netlink.SkbEditAction)
		Expect(ok).To(BeTrue())
		Expect(skb.Priority).ToNot(BeNil())
		Expect(*skb.Priority).To(Equal(adqf.TC))

		Expect(skb.Mark).To(BeNil())
		Expect(skb.QueueMapping).To(BeNil())

		skb, ok = flower.Actions[1].(*netlink.SkbEditAction)
		Expect(ok).To(BeTrue())
		Expect(skb.QueueMapping).ToNot(BeNil())
		Expect(*skb.QueueMapping).To(Equal(adqf.QueueNumber + 1))

		Expect(skb.Priority).To(BeNil())
		Expect(skb.Mark).To(BeNil())
	})

	var _ = It("return valid flower filter if passed data is valid (adq-shared) TUNNELING_VXLAN", func() {
		adqf := AdqFilter{
			IpAddress:   net.ParseIP("10.123.123.1"),
			Tunnel:      TUNNELING_VXLAN,
			TC:          3,
			IpProto:     StringToIpProto("TCP"),
			PortValue:   12345,
			Dir:         DirectionLocal,
			QueueNumber: 128,
			FilterPrio:  1,
		}

		f, err := CreateEgressFlower(5, adqf)
		Expect(err).ToNot(HaveOccurred())
		Expect(f).ToNot(BeNil())

		flower, ok := f.(*netlink.Flower)
		Expect(ok).To(BeTrue())
		Expect(flower.Attrs().LinkIndex).To(Equal(5))
		Expect(flower.Attrs().Parent).To(Equal(uint32(netlink.HANDLE_MIN_EGRESS)))
		Expect(flower.Attrs().Priority).To(Equal(uint16(adqf.FilterPrio)))
		Expect(flower.Attrs().Protocol).To(Equal(uint16(unix.ETH_P_IP)))
		Expect(flower.Attrs().Handle).To(Equal(uint32(0)))

		Expect(flower.EthType).To(Equal(uint16(unix.ETH_P_IP)))
		Expect(flower.IPProto).To(Equal(adqf.IpProto))
		Expect(flower.SrcIP).To(Equal(adqf.IpAddress))
		Expect(flower.DestIP).To(Equal(net.IP(nil)))
		Expect(flower.TcpSrcPort).To(Equal(uint16(12345)))
		Expect(flower.TcpDestPort).To(Equal(uint16(0)))
		Expect(flower.UdpDestPort).To(Equal(uint16(0)))
		Expect(flower.UdpSrcPort).To(Equal(uint16(0)))

		Expect(flower.Actions).To(HaveLen(1))
		skb, ok := flower.Actions[0].(*netlink.SkbEditAction)
		Expect(ok).To(BeTrue())
		Expect(skb.Mark).ToNot(BeNil())
		Expect(*skb.Mark).To(Equal(adqf.TC))

		Expect(skb.Priority).To(BeNil())
		Expect(skb.QueueMapping).To(BeNil())
	})
})

var _ = Describe("CreateEgressU32 should", func() {
	var _ = It("return error if provided TC value exceeds max", func() {
		adqf := AdqFilter{
			IpAddress: net.ParseIP("10.123.123.1"),
			Tunnel:    TUNNELING_DISABLED,
			TC:        25,
		}

		f, err := CreateEgressU32(5, adqf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("provided hw_tc:25 exceeds max 0x000F"))
		Expect(f).To(BeNil())

	})

	var _ = It("return valid U32 filter if passed data is valid", func() {
		adqf := AdqFilter{
			IpAddress:   net.ParseIP("10.123.123.1"),
			Tunnel:      TUNNELING_DISABLED,
			TC:          3,
			IpProto:     StringToIpProto("TCP"),
			PortValue:   12345,
			Dir:         DirectionLocal,
			QueueNumber: 128,
			FilterPrio:  1,
		}

		f, err := CreateEgressU32(5, adqf)
		Expect(err).ToNot(HaveOccurred())
		Expect(f).ToNot(BeNil())

		egress, ok := f.(*netlink.U32)
		Expect(ok).To(BeTrue())
		Expect(egress.FilterAttrs.LinkIndex).To(Equal(5))
		Expect(egress.FilterAttrs.Parent).To(Equal(uint32(netlink.HANDLE_MIN_EGRESS)))
		Expect(egress.FilterAttrs.Priority).To(Equal(uint16(adqf.FilterPrio)))
		Expect(egress.FilterAttrs.Protocol).To(Equal(uint16(unix.ETH_P_IP)))
		Expect(egress.FilterAttrs.Handle).To(Equal(uint32(0)))

		Expect(egress.Sel).ToNot(BeNil())
		Expect(egress.Sel.Keys).To(BeNil())
		Expect(egress.Sel.Flags).To(Equal(uint8(netlink.TC_U32_TERMINAL)))

		Expect(egress.Mark).ToNot(BeNil())
		Expect(egress.Mark.Val).To(Equal(adqf.TC))
		Expect(egress.Mark.Mask).To(Equal(uint32(0xFF)))

		Expect(egress.Actions).To(HaveLen(2))
		skb, ok := egress.Actions[0].(*netlink.SkbEditAction)
		Expect(ok).To(BeTrue())
		Expect(*skb.Priority).To(Equal(adqf.TC))

		Expect(skb.Mark).To(BeNil())
		Expect(skb.QueueMapping).To(BeNil())

		skb, ok = egress.Actions[1].(*netlink.SkbEditAction)
		Expect(ok).To(BeTrue())
		Expect(*skb.QueueMapping).To(Equal(adqf.QueueNumber + 1))

		Expect(skb.Mark).To(BeNil())
		Expect(skb.Priority).To(BeNil())
	})
})

var _ = Describe("TCDelFlowerFilters should remove error if", func() {
	var _ = It("netlink.FilterList returns error", func() {
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return nil, errors.New("filter list error")
		}

		ntc := &NetlinkTcObject{}

		deletedFlowers, err := ntc.TCDelFlowerFilters(net.ParseIP("10.123.123.1"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("filter list error"))

		Expect(deletedFlowers).To(BeNil())

	})
})

var _ = Describe("TCDelMatchingU32Filters should remove error if", func() {
	var _ = It("netlink.FilterList returns error", func() {
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return nil, errors.New("filter list error")
		}

		ntc := &NetlinkTcObject{}

		err := ntc.TCDelMatchingU32Filters(nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("filter list error"))
	})
})

var _ = Describe("TCDelFlowerFilters should remove all flower filters for passed IP address and return removed filter list if", func() {
	var _ = It("it is able to retrieve matching filters", func() {

		ipAddr := net.ParseIP("10.123.123.1")
		queueMapping := uint16(128)

		filterListEgress := []netlink.Filter{
			&netlink.U32{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: 5,
				},
			},

			&netlink.Flower{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: 5,
					Parent:    netlink.HANDLE_MIN_EGRESS,
				},
				SrcIP: ipAddr,
				Actions: []netlink.Action{
					&netlink.SkbEditAction{
						QueueMapping: &queueMapping,
					},
				},
			},
		}

		filterListIngress := []netlink.Filter{
			&netlink.U32{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: 5,
				},
			},

			&netlink.Flower{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: 5,
					Parent:    netlink.HANDLE_MIN_INGRESS + 1,
				},
				DestIP:  ipAddr,
				ClassID: 3,
			},
		}

		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			if parent == netlink.HANDLE_MIN_EGRESS {
				return filterListEgress, nil

			} else if parent == netlink.HANDLE_INGRESS+1 {
				return filterListIngress, nil
			}
			return nil, nil
		}

		ntc := &NetlinkTcObject{}

		requestedDelFilters := []netlink.Filter{}
		netlinkFilterDel = func(f netlink.Filter) error {
			requestedDelFilters = append(requestedDelFilters, f)
			return nil
		}

		deletedFlowers, err := ntc.TCDelFlowerFilters(ipAddr)
		Expect(err).ToNot(HaveOccurred())
		Expect(deletedFlowers).To(HaveLen(2))

		Expect(deletedFlowers[0].SrcIP).To(Equal(ipAddr))
		Expect(deletedFlowers[0].DestIP).To(Equal(net.IP(nil)))

		Expect(deletedFlowers[1].DestIP).To(Equal(ipAddr))
		Expect(deletedFlowers[1].SrcIP).To(Equal(net.IP(nil)))

		Expect(requestedDelFilters).To(HaveLen(2))

		f, ok := requestedDelFilters[0].(*netlink.Flower)
		Expect(ok).To(BeTrue())

		Expect(f.SrcIP).To(Equal(ipAddr))
		Expect(f.DestIP).To(Equal(net.IP(nil)))

		f, ok = requestedDelFilters[1].(*netlink.Flower)
		Expect(ok).To(BeTrue())

		Expect(f.DestIP).To(Equal(ipAddr))
		Expect(f.SrcIP).To(Equal(net.IP(nil)))
	})
})

var _ = Describe("TCDelMatchingU32Filters should remove all U32 filters if", func() {
	var _ = It("matching flower filters are passed", func() {

		ipAddr := net.ParseIP("10.123.123.1")
		queueMapping := uint16(128)
		maj, min := netlink.MajorMinor(uint32(queueMapping) + handleSharedClassID)
		handle := netlink.MakeHandle(maj, min)

		removedFlowers := []*netlink.Flower{
			{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: 5,
					Parent:    netlink.HANDLE_MIN_EGRESS,
				},
				SrcIP: ipAddr,
				Actions: []netlink.Action{
					&netlink.SkbEditAction{
						QueueMapping: &queueMapping,
					},
				},
				ClassID: handle,
			},
		}

		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return []netlink.Filter{
				&netlink.U32{
					FilterAttrs: netlink.FilterAttrs{
						LinkIndex: 5,
					},
					Actions: []netlink.Action{
						&netlink.SkbEditAction{
							QueueMapping: &queueMapping,
						},
					},

					Mark: &nl.TcU32Mark{
						Val:  3,
						Mask: 0xFF,
					},
				},

				&netlink.U32{
					FilterAttrs: netlink.FilterAttrs{
						LinkIndex: 5,
					},

					Mark: &nl.TcU32Mark{
						Val:  2,
						Mask: 0xFF,
					},
				},
			}, nil
		}

		ntc := &NetlinkTcObject{}

		requestedDelFilters := []netlink.Filter{}
		netlinkFilterDel = func(f netlink.Filter) error {
			requestedDelFilters = append(requestedDelFilters, f)
			return nil
		}

		err := ntc.TCDelMatchingU32Filters(removedFlowers)
		Expect(err).ToNot(HaveOccurred())
		Expect(requestedDelFilters).To(HaveLen(1))

		f, ok := requestedDelFilters[0].(*netlink.U32)
		Expect(ok).To(BeTrue())
		Expect(f.Mark.Val).To(Equal(uint32(3)))
	})
})

var _ = Describe("GetSharedTC", func() {
	var _ = It("should return error if no TCs are allocated", func() {

		mqprio := netlink.MqPrio{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: 5,
				Handle:    1,
				Parent:    2,
			},
			Opt: nl.TcMqPrioQopt{},
		}

		ntc := &NetlinkTcObject{
			mqprioQdisc: &mqprio,
		}

		val, err := ntc.GetSharedTC()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("need at least one TC to be allocated, found none"))

		Expect(val).To(Equal(uint8(0)))
	})

	var _ = It("should return number of the last TC", func() {

		mqprio := netlink.MqPrio{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: 5,
				Handle:    1,
				Parent:    2,
			},
			Opt: nl.TcMqPrioQopt{
				NumTc: 6,
			},
		}

		ntc := &NetlinkTcObject{
			mqprioQdisc: &mqprio,
		}

		val, err := ntc.GetSharedTC()
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal(uint8(5)))
	})
})

var _ = Describe("TCGetStartStopQ", func() {
	var _ = It("should return error if requested TC is not provisioned", func() {

		mqprio := netlink.MqPrio{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: 5,
				Handle:    1,
				Parent:    2,
			},
			Opt: nl.TcMqPrioQopt{
				NumTc: 6,
			},
		}

		ntc := &NetlinkTcObject{
			mqprioQdisc: &mqprio,
		}

		startq, stopq, err := ntc.TCGetStartStopQ(7)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("requested tc 7 is not provisioned, max: 5"))

		Expect(startq).To(Equal(uint16(0)))
		Expect(stopq).To(Equal(uint16(0)))
	})

	var _ = It("should return valid startQ and stopQ if valid TC is passed", func() {

		mqprio := netlink.MqPrio{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: 5,
				Handle:    1,
				Parent:    2,
			},
			Opt: nl.TcMqPrioQopt{ // queues:(0:15) (16:19) (20:23) (24:27) (28:31) (32:63)
				NumTc: 6,
				Count: [16]uint16{
					16,
					4,
					4,
					4,
					4,
					32,
				},
				Offset: [16]uint16{
					0,
					16,
					20,
					24,
					28,
					32,
				},
			},
		}

		ntc := &NetlinkTcObject{
			mqprioQdisc: &mqprio,
		}

		startq, stopq, err := ntc.TCGetStartStopQ(1)
		Expect(err).ToNot(HaveOccurred())

		Expect(startq).To(Equal(uint16(16)))
		Expect(stopq).To(Equal(uint16(19)))
	})
})

var _ = Describe("GetHWClassID", func() {
	var _ = It("should return error if requested TC exceeds the max value", func() {
		val, err := GetHWClassID(16)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("provided hw_tc:16 exceeds max 0x000F"))
		Expect(val).To(Equal(uint32(15)))
	})

	var _ = It("should return valid ClassID if provided value is in range", func() {
		val, err := GetHWClassID(15)
		Expect(err).ToNot(HaveOccurred())
		clid := 15 + netlink.HANDLE_MIN_INGRESS
		Expect(val).To(Equal(uint32(clid)))
	})
})
