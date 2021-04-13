package main

import (
	"bytes"
	"errors"
	"net"
	"regexp"
	"strings"
	"testing"

	"github.com/intel/adq-device-plugin/pkg/kubeletclient"
	"github.com/intel/adq-device-plugin/pkg/netlinktc"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"
)

func TestAdqExporter(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ADQ exporter Test Suite")
}

var (
	fakeInterfaces          []net.Interface
	fakeGetNetInterfacesErr error

	adqm                  netlinktc.NetlinkTcMock
	kcmock                kubeletclient.KubeletClientMock
	getKubeletClientError error

	ethtoolSupportedStatNamesStored []string
)

type ethtoolMock struct {
	stats    map[string]interfaceStats
	statsErr map[string]error

	driverName    map[string]string
	driverNameErr map[string]error
}

func AdqTCInit(ifname string, virtual bool) (netlinktc.NetlinkTc, error) {
	adqm.InitMaster = ifname
	return &adqm, adqm.AdqTCInitError
}

var fakeGetNetInterfaces = func() ([]net.Interface, error) {
	return fakeInterfaces, fakeGetNetInterfacesErr
}

var getKubeletClientMock = func(bool, string, string, string) (kubeletclient.KubeletClient, error) {
	return &kcmock, getKubeletClientError
}

var _ = BeforeEach(func() {
	ethtoolSupportedStatNamesStored = ethtoolSupportedStatNames
	getKubeletClientError = nil
	adqm.AdqTCInitError = nil
})

var _ = AfterEach(func() {
	ethtoolSupportedStatNames = ethtoolSupportedStatNamesStored
})

func (e *ethtoolMock) Stats(intf string) (map[string]uint64, error) {
	return e.stats[intf], e.statsErr[intf]
}

func (e *ethtoolMock) DriverName(intf string) (string, error) {
	return e.driverName[intf], e.driverNameErr[intf]
}

var _ = Describe("getMatchingStats should return error if", func() {
	var _ = It("ethHandle is not initialized", func() {
		adqcol := adqCollector{}
		_, err := adqcol.getMatchingStats()
		Expect(err).To(HaveOccurred())
	})

	var _ = It("getNetInterfaces fails", func() {
		adqcol := adqCollector{
			ethHandle: &ethtoolMock{},
		}

		fakeGetNetInterfacesErr = errors.New("GetNetInterfacesErr")
		getNetInterfaces = fakeGetNetInterfaces

		_, err := adqcol.getMatchingStats()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("GetNetInterfacesErr"))
	})
})

var _ = Describe("getMatchingStats should return valid stats if", func() {
	var _ = It("for any interface that uses ice driver", func() {

		fakeInterfaces = []net.Interface{
			{
				Index: 0,
				Name:  "eth0",
			},
			{
				Index: 1,
				Name:  "eth1",
			},
			{
				Index: 2,
				Name:  "eth2",
			},
			{
				Index: 3,
				Name:  "eth3",
			},
		}
		fakeGetNetInterfacesErr = nil
		getNetInterfaces = fakeGetNetInterfaces

		etm := ethtoolMock{}
		etm.stats = make(map[string]interfaceStats)
		etm.statsErr = make(map[string]error)
		etm.driverName = make(map[string]string)
		etm.driverNameErr = make(map[string]error)

		// eth0
		etm.driverNameErr["eth0"] = errors.New("eth0 driver name error")
		etm.statsErr["eth0"] = nil

		// eth1
		etm.driverNameErr["eth1"] = nil
		etm.statsErr["eth1"] = nil
		etm.driverName["eth1"] = "not_ice"

		//eth2
		etm.driverNameErr["eth2"] = nil
		etm.statsErr["eth2"] = errors.New("eth2 stats error")
		etm.driverName["eth2"] = "ice"

		//eth3
		etm.driverNameErr["eth3"] = nil
		etm.statsErr["eth3"] = nil
		etm.driverName["eth3"] = "ice"

		etm.stats["eth3"] = make(map[string]uint64)
		etm.stats["eth3"]["pkt_busy_poll"] = 21
		etm.stats["eth3"]["pkt_not_busy_poll"] = 12

		r, err := regexp.Compile(strings.Join(ethtoolSupportedStatNames, "|"))
		Expect(err).ToNot(HaveOccurred())

		adqcol := adqCollector{
			matchingStatsRegex: r,
			ethHandle:          &etm,
		}

		result, err := adqcol.getMatchingStats()
		Expect(err).ToNot(HaveOccurred())
		Expect(result).To(HaveLen(1))
		Expect(result["eth3"]["pkt_busy_poll"]).To(Equal(uint64(21)))
		Expect(result["eth3"]["pkt_not_busy_poll"]).To(Equal(uint64(12)))
	})
})

var _ = Describe("NewAdqCollector should return error if", func() {
	var _ = It("is unable to initialize ethtool", func() {
		getEthtool = func() (ethtoolInterface, error) { return nil, errors.New("getEthtool error") }
		adqc, err := NewAdqCollector()
		Expect(adqc).To(BeNil())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Unable to create ethtool handler"))
	})

	var _ = It("invalid stat name causes regexp compile error", func() {
		getEthtool = func() (ethtoolInterface, error) { return &ethtoolMock{}, nil }
		ethtoolSupportedStatNames = []string{"("}
		adqc, err := NewAdqCollector()
		Expect(adqc).To(BeNil())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Unable to compile regex for matching stats"))
	})

	var _ = It("is not able to get matching stats", func() {
		fakeGetNetInterfacesErr = errors.New("get stats error")
		getNetInterfaces = fakeGetNetInterfaces
		etm := ethtoolMock{}
		getEthtool = func() (ethtoolInterface, error) { return &etm, nil }
		adqc, err := NewAdqCollector()
		Expect(adqc).To(BeNil())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Unable to retrieve matching stats"))
	})
})

var _ = Describe("NewAdqCollector should return valid collector object if", func() {
	var _ = It("it's able to initialize it without errors", func() {
		fakeInterfaces = []net.Interface{
			{
				Index: 0,
				Name:  "eth0",
			},
		}
		fakeGetNetInterfacesErr = nil
		getNetInterfaces = fakeGetNetInterfaces

		etm := ethtoolMock{}
		etm.stats = make(map[string]interfaceStats)
		etm.statsErr = make(map[string]error)
		etm.driverName = make(map[string]string)
		etm.driverNameErr = make(map[string]error)

		etm.driverNameErr["eth0"] = nil
		etm.statsErr["eth0"] = nil
		etm.driverName["eth0"] = "ice"

		etm.stats["eth0"] = make(map[string]uint64)
		etm.stats["eth0"]["tx_123.pkt_busy_poll"] = 21
		etm.stats["eth0"]["rx_123.pkt_busy_poll"] = 12

		getEthtool = func() (ethtoolInterface, error) { return &etm, nil }
		adqc, err := NewAdqCollector()
		Expect(adqc).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
	})
})

var _ = Describe("getLabels should return valid labels if", func() {
	var _ = It("passed queue number matches pod TC", func() {

		pr := podresourcesapi.PodResources{
			Name:      "testpod",
			Namespace: "testnamespace",
			Containers: []*podresourcesapi.ContainerResources{
				{
					Name: "c1",
					Devices: []*podresourcesapi.ContainerDevices{
						{
							ResourceName: "someresource",
							DeviceIds:    []string{"nan"},
						},
						{
							ResourceName: "someresource",
							DeviceIds:    []string{"1"},
						},
						{
							ResourceName: "net.intel.com/adq",
							DeviceIds:    []string{"2"},
						},
					},
				},

				{
					Name: "c2",
					Devices: []*podresourcesapi.ContainerDevices{
						{
							ResourceName: "net.intel.com/adq-shared",
							DeviceIds:    []string{"55"},
						},
					},
				},
				{
					Name: "c3",
					Devices: []*podresourcesapi.ContainerDevices{
						{
							ResourceName: "net.intel.com/adq-shared",
							DeviceIds:    []string{"25"},
						},
					},
				},
			},
		}

		// adq-exclusive
		adqm := netlinktc.NetlinkTcMock{
			StartQ: 1,
			StopQ:  3,
		}

		labels := getLabels(&pr, &adqm, 2)
		Expect(labels.tcNumber).To(Equal("2"))
		Expect(labels.containerName).To(Equal("c1"))
		Expect(labels.podName).To(Equal("testpod"))
		Expect(labels.podNamespace).To(Equal("testnamespace"))
		Expect(labels.podAdqResource).To(Equal(kubeletclient.AdqResourceName))

		adqm.StartStopErr = errors.New("TCGetStartStopQ error")
		labels = getLabels(&pr, &adqm, 2)
		Expect(labels).To(Equal(adqLabels{}))

		adqm.StartStopErr = nil
		labels = getLabels(&pr, &adqm, 10)
		Expect(labels).To(Equal(adqLabels{}))

		// adq-shared
		adqm = netlinktc.NetlinkTcMock{
			StartQ: 20,
			StopQ:  30,
		}
		adqm.SharedTCNum = 5
		labels = getLabels(&pr, &adqm, 25)
		Expect(labels.tcNumber).To(Equal("5"))
		Expect(labels.containerName).To(Equal("c3"))
		Expect(labels.podName).To(Equal("testpod"))
		Expect(labels.podNamespace).To(Equal("testnamespace"))
		Expect(labels.podAdqResource).To(Equal(kubeletclient.AdqSharedResourceName))

		adqm.StartStopErr = errors.New("TCGetStartStopQ error")
		labels = getLabels(&pr, &adqm, 25)
		Expect(labels).To(Equal(adqLabels{}))

	})
})

var _ = Describe("Collect should not push valid metric to the channel if", func() {

	etm := ethtoolMock{}
	etm.stats = make(map[string]interfaceStats)
	etm.statsErr = make(map[string]error)
	etm.driverName = make(map[string]string)
	etm.driverNameErr = make(map[string]error)

	etm.driverNameErr["eth0"] = nil
	etm.statsErr["eth0"] = nil
	etm.driverName["eth0"] = "ice"

	etm.stats["eth0"] = make(map[string]uint64)
	etm.stats["eth0"]["pkt_busy_poll"] = 21
	etm.stats["eth0"]["pkt_not_busy_poll"] = 12

	var _ = It("getMatchingStats returns error", func() {
		var buf bytes.Buffer
		log.SetOutput(&buf)

		ch := make(chan prometheus.Metric)
		adqcol := adqCollector{}
		adqcol.Collect(ch)

		Expect(buf.String()).To(ContainSubstring("Unable to retrieve matching stats:ethtool handler not initialized"))
		Expect(ch).To(BeEmpty())
	})

	var _ = It("getKubeletClient returns error", func() {
		var buf bytes.Buffer
		log.SetOutput(&buf)

		ch := make(chan prometheus.Metric)

		fakeInterfaces = []net.Interface{
			{
				Index: 0,
				Name:  "eth0",
			},
		}
		fakeGetNetInterfacesErr = nil
		getNetInterfaces = fakeGetNetInterfaces

		adqtcInit = AdqTCInit

		getKubeletClientError = errors.New("get kubeletclient error")
		getKubeletClient = getKubeletClientMock

		r, err := regexp.Compile(strings.Join(ethtoolSupportedStatNames, "|"))
		Expect(err).ToNot(HaveOccurred())

		adqcol := adqCollector{
			matchingStatsRegex: r,
			ethHandle:          &etm,
		}

		adqcol.Collect(ch)

		Expect(buf.String()).To(ContainSubstring("Unable to get kubeletclient"))
		Expect(ch).To(BeEmpty())
	})

	var _ = It("adqtcInit returns error", func() {
		var buf bytes.Buffer
		log.SetOutput(&buf)

		ch := make(chan prometheus.Metric)

		fakeInterfaces = []net.Interface{
			{
				Index: 0,
				Name:  "eth0",
			},
		}
		fakeGetNetInterfacesErr = nil
		getNetInterfaces = fakeGetNetInterfaces

		adqm.AdqTCInitError = errors.New("adqtc init error")
		adqtcInit = AdqTCInit

		r, err := regexp.Compile(strings.Join(ethtoolSupportedStatNames, "|"))
		Expect(err).ToNot(HaveOccurred())

		adqcol := adqCollector{
			matchingStatsRegex: r,
			ethHandle:          &etm,
		}

		adqcol.Collect(ch)

		Expect(buf.String()).To(ContainSubstring("Cannot initialize tc module for interface:eth0"))
		Expect(ch).To(BeEmpty())
	})
})

var _ = Describe("Collect should push valid metric to the channel if", func() {
	var _ = It("is able to retrieve valid data", func() {
		var buf bytes.Buffer
		log.SetOutput(&buf)

		etm := ethtoolMock{}
		etm.stats = make(map[string]interfaceStats)
		etm.statsErr = make(map[string]error)
		etm.driverName = make(map[string]string)
		etm.driverNameErr = make(map[string]error)

		etm.driverNameErr["eth0"] = nil
		etm.statsErr["eth0"] = nil
		etm.driverName["eth0"] = "ice"

		etm.stats["eth0"] = make(map[string]uint64)
		etm.stats["eth0"]["tx_123.pkt_busy_poll"] = 12

		ch := make(chan prometheus.Metric, 2)

		fakeInterfaces = []net.Interface{
			{
				Index: 0,
				Name:  "eth0",
			},
		}
		fakeGetNetInterfacesErr = nil
		getNetInterfaces = fakeGetNetInterfaces

		adqtcInit = AdqTCInit

		getKubeletClientError = nil
		kcm := kubeletclient.KubeletClientMock{}
		kcm.PodResources = []*podresourcesapi.PodResources{
			{
				Name:      "testpod",
				Namespace: "testnamespace",
				Containers: []*podresourcesapi.ContainerResources{
					{
						Name: "c1",
						Devices: []*podresourcesapi.ContainerDevices{
							{
								ResourceName: "net.intel.com/adq",
								DeviceIds:    []string{"2"},
							},
						},
					},
				},
			},
		}

		getKubeletClient = func(bool, string, string, string) (kubeletclient.KubeletClient, error) {
			return &kcm, nil
		}

		getEthtool = func() (ethtoolInterface, error) { return &etm, nil }
		adqc, err := NewAdqCollector()
		Expect(adqc).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())

		adqc.Collect(ch)

		Expect(ch).ToNot(BeEmpty())

		m := <-ch

		Expect(m.Desc().String()).To(ContainSubstring("adq_tx_pkt_busy_poll"))
	})
})

var _ = Describe("Describe should push valid descriptions to the channel if", func() {
	var _ = It("adq collector is initialized correctly", func() {
		var buf bytes.Buffer
		log.SetOutput(&buf)

		etm := ethtoolMock{}
		etm.stats = make(map[string]interfaceStats)
		etm.statsErr = make(map[string]error)
		etm.driverName = make(map[string]string)
		etm.driverNameErr = make(map[string]error)

		etm.driverNameErr["eth0"] = nil
		etm.statsErr["eth0"] = nil
		etm.driverName["eth0"] = "ice"

		etm.stats["eth0"] = make(map[string]uint64)
		etm.stats["eth0"]["tx_123.pkt_busy_poll"] = 12

		ch := make(chan *prometheus.Desc, 2)

		fakeInterfaces = []net.Interface{
			{
				Index: 0,
				Name:  "eth0",
			},
		}
		fakeGetNetInterfacesErr = nil
		getNetInterfaces = fakeGetNetInterfaces

		getEthtool = func() (ethtoolInterface, error) { return &etm, nil }
		adqc, err := NewAdqCollector()
		Expect(adqc).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())

		adqc.Describe(ch)

		Expect(ch).ToNot(BeEmpty())

		d := <-ch

		Expect(d.String()).To(ContainSubstring("adq_tx_pkt_busy_poll"))
		Expect(d.String()).To(ContainSubstring("adq_node_name"))
		Expect(d.String()).To(ContainSubstring("adq_nic"))
		Expect(d.String()).To(ContainSubstring("adq_pod_name"))
		Expect(d.String()).To(ContainSubstring("adq_pod_namespace"))
		Expect(d.String()).To(ContainSubstring("adq_container_name"))
		Expect(d.String()).To(ContainSubstring("adq_pod_adq_resource"))
		Expect(d.String()).To(ContainSubstring("adq_queue_number"))
		Expect(d.String()).To(ContainSubstring("adq_tc_number"))
	})
})
