// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation

package plugin

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/intel/adq-device-plugin/pkg/kubeletclient"
	"github.com/intel/adq-device-plugin/pkg/netlinktc"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	v1 "k8s.io/api/core/v1"
	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"
)

func TestKubeletClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "plugin Test Suite")
}

const nodeConfigJ = `
{                                                                                                                                                                                                                                                                                                                                
    "EgressMode": "skbedit",                                                                                                                                                                                                                                                                                                     
    "FilterPrio": 1,                                                                                                                                                                                                                                                                                                             
    "Globals": {                                                                                                                                                                                                                                                                                                                 
        "Dev": "ens801f0"                                                                                                                                                                                                                                                                                                      
    }
}
`

var _ = BeforeSuite(func() {
	f, err := ioutil.TempFile("/tmp", "")
	Expect(err).NotTo(HaveOccurred())

	err = os.WriteFile(f.Name(), []byte(nodeConfigJ), 0644)
	Expect(err).NotTo(HaveOccurred())

	defaultNodeConfigPath = f.Name()

})

var _ = AfterSuite(func() {

})

var (
	kClientMock     *kubeletClientMock
	kClientGetError error
	adqm            *netlinktc.NetlinkTcMock
	linkMock        *LinkMock
)

func adqTCInit(ifname string, virtual bool) (netlinktc.NetlinkTc, error) {
	adqm.InitMaster = ifname
	return adqm, adqm.AdqTCInitError
}

type kubeletClientMock struct {
	resourceMap       []*kubeletclient.ResourceInfo
	getResourceMapErr error

	adqConfig       []*kubeletclient.AdqConfigEntry
	getAdqConfigErr error
}

func (kcm *kubeletClientMock) GetPodResourceMap(podName string, podNamespace string,
	master string) ([]*kubeletclient.ResourceInfo, error) {
	return kcm.resourceMap, kcm.getResourceMapErr
}

func (kcm *kubeletClientMock) GetAdqConfig(podName string,
	podNamespace string) ([]*kubeletclient.AdqConfigEntry, error) {
	return kcm.adqConfig, kcm.getAdqConfigErr
}

func (kcm *kubeletClientMock) GetPodList() (*v1.PodList, error) {
	return nil, nil // to be implemented
}

func (kcm *kubeletClientMock) GetPodResources() []*podresourcesapi.PodResources {
	return nil // to be implemented
}

func (kcm *kubeletClientMock) SyncPodResources() error {
	return nil // to be implemented
}

func GetKubeletClientMock(httpClientEnabled bool, ksName, ksPort, caPath string) (kubeletclient.KubeletClient, error) {
	return kClientMock, kClientGetError
}

func WithNetNSPathMock(nspath string, toRun func(ns.NetNS) error) error {
	return toRun(nil)
}

type LinkMock struct {
	linkByNameErr error
	addrListErr   error
	attrs         netlink.LinkAttrs
	linkType      string
	addrs         []netlink.Addr
}

func (l *LinkMock) Attrs() *netlink.LinkAttrs {
	return &l.attrs
}

func (l *LinkMock) Type() string {
	return l.linkType
}

func LinkByNameMock(name string) (netlink.Link, error) {
	return linkMock, linkMock.linkByNameErr
}

func AddrListMock(link netlink.Link, family int) ([]netlink.Addr, error) {
	return linkMock.addrs, linkMock.addrListErr
}

var _ = Describe("CmdAdd should return error if", func() {
	var _ = It("is called with invalid args", func() {
		args := skel.CmdArgs{
			Args: "someinvaliddata",
		}
		err := CmdAdd(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Unable to load args"))
	})

	var _ = It("is called with invalid stdin data", func() {
		args := skel.CmdArgs{
			StdinData: []byte("someinvaliddata"),
		}
		err := CmdAdd(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Loading network configuration unsuccessful"))
	})

	var _ = It("is called with valid stdin data but empty master value and is unable to read discovered one", func() {
		n := &adqConf{}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args := skel.CmdArgs{
			StdinData: j,
		}
		old := defaultNodeConfigPath
		defaultNodeConfigPath = "./someinvalidpath"

		err = CmdAdd(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Unable to read node config"))
		defaultNodeConfigPath = old
	})

	var _ = It("is called with missing RawPrevResult", func() {
		n := &adqConf{}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args := skel.CmdArgs{
			StdinData: j,
		}
		err = CmdAdd(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Required prev result is missing"))
	})

	var _ = It("is not able to parse RawPrevResult", func() {
		nr := current.Result{
			CNIVersion: "0.4.0",
		}

		value := map[string]int{
			"someinvaliddata": 123,
		}
		rawResult := map[string]interface{}{
			"CNIVersion": value,
		}

		n := &adqConf{
			NetConf: types.NetConf{
				PrevResult:    &nr,
				RawPrevResult: rawResult,
			},
		}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args := skel.CmdArgs{
			StdinData: j,
		}

		err = CmdAdd(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("could not parse prevResult"))
	})

	var _ = It("is not able to get kubelet client", func() {
		getKubeletClient = GetKubeletClientMock

		nr := current.Result{
			CNIVersion: "0.4.0",
		}

		rawResult := map[string]interface{}{
			"CNIVersion": "0.4.0",
		}

		n := &adqConf{
			NetConf: types.NetConf{
				PrevResult:    &nr,
				RawPrevResult: rawResult,
			},
		}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args := skel.CmdArgs{
			StdinData: j,
		}

		kClientMock = &kubeletClientMock{}
		kClientGetError = errors.New("testerr")

		err = CmdAdd(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("testerr"))
	})

	var _ = It("gets result with empty IP", func() {
		getKubeletClient = GetKubeletClientMock

		nr := current.Result{
			CNIVersion: "0.4.0",
		}

		rawResult := map[string]interface{}{
			"CNIVersion": "0.4.0",
		}

		n := &adqConf{
			NetConf: types.NetConf{
				PrevResult:    &nr,
				RawPrevResult: rawResult,
			},
		}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args := skel.CmdArgs{
			StdinData: j,
		}

		kClientMock = &kubeletClientMock{}
		kClientGetError = nil

		err = CmdAdd(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("IP address not set"))
	})

	var _ = It("GetAdqConfig returns error", func() {
		kClientMock = &kubeletClientMock{}
		kClientGetError = nil

		_, ipnet, _ := net.ParseCIDR("10.123.123.1/24")
		prevRes := current.Result{
			CNIVersion: "0.4.0",
			IPs: []*current.IPConfig{
				{
					Version: "4",
					Address: *ipnet,
				},
			},
		}

		// convert struct to map[string]interface{}
		temp, err := json.Marshal(prevRes)
		Expect(err).ToNot(HaveOccurred())
		raw := make(map[string]interface{})
		err = json.Unmarshal(temp, &raw)
		Expect(err).ToNot(HaveOccurred())

		n := &adqConf{
			NetConf: types.NetConf{
				CNIVersion:    "0.4.0",
				PrevResult:    &prevRes,
				RawPrevResult: raw,
			},
		}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args := skel.CmdArgs{
			StdinData: j,
		}

		kClientMock.resourceMap = []*kubeletclient.ResourceInfo{
			{
				TC:            "5",
				ContainerName: "container1",
			},
		}

		kClientMock.getAdqConfigErr = errors.New("GetAdqConfig error")

		adqm = &netlinktc.NetlinkTcMock{}
		adqtcInit = adqTCInit

		err = CmdAdd(&args)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("GetAdqConfig error"))
	})

	var _ = It("addTC returns error", func() {
		kClientMock = &kubeletClientMock{}
		kClientGetError = nil

		_, ipnet, _ := net.ParseCIDR("10.123.123.1/24")
		prevRes := current.Result{
			CNIVersion: "0.4.0",
			IPs: []*current.IPConfig{
				{
					Version: "4",
					Address: *ipnet,
				},
			},
		}

		// convert struct to map[string]interface{}
		temp, err := json.Marshal(prevRes)
		Expect(err).ToNot(HaveOccurred())
		raw := make(map[string]interface{})
		err = json.Unmarshal(temp, &raw)
		Expect(err).ToNot(HaveOccurred())

		n := &adqConf{
			NetConf: types.NetConf{
				CNIVersion:    "0.4.0",
				PrevResult:    &prevRes,
				RawPrevResult: raw,
			},
		}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args := skel.CmdArgs{
			StdinData: j,
		}

		kClientMock.resourceMap = []*kubeletclient.ResourceInfo{
			{
				TC:            "5",
				ContainerName: "container1",
			},
		}

		adqm = &netlinktc.NetlinkTcMock{}
		adqtcInit = adqTCInit
		adqm.AdqTCInitError = errors.New("adqtcInit error")

		err = CmdAdd(&args)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("adqtcInit error"))

		adqm.AdqTCInitError = nil
		adqm.AddFilterErr = errors.New("TCAddFilter error")
		err = CmdAdd(&args)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("TCAddFilter error"))
	})
})

var _ = Describe("CmdAdd should return no error and call TCAddFilter() if", func() {
	var args skel.CmdArgs
	var ipnet *net.IPNet
	var _ = BeforeEach(func() {
		getKubeletClient = GetKubeletClientMock

		_, ipnet, _ = net.ParseCIDR("10.123.123.1/24")
		prevRes := current.Result{
			CNIVersion: "0.4.0",
			IPs: []*current.IPConfig{
				{
					Version: "4",
					Address: *ipnet,
				},
			},
		}

		// convert struct to map[string]interface{}
		temp, err := json.Marshal(prevRes)
		Expect(err).ToNot(HaveOccurred())
		raw := make(map[string]interface{})
		err = json.Unmarshal(temp, &raw)
		Expect(err).ToNot(HaveOccurred())

		n := &adqConf{
			NetConf: types.NetConf{
				CNIVersion:    "0.4.0",
				PrevResult:    &prevRes,
				RawPrevResult: raw,
			},
		}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args = skel.CmdArgs{
			StdinData: j,
		}
	})

	var _ = Context("is able to retrive valid data from kubeletclient", func() {
		var _ = It("ADQ config contains ports", func() {
			kClientMock = &kubeletClientMock{}
			kClientGetError = nil

			kClientMock.resourceMap = []*kubeletclient.ResourceInfo{
				{
					TC:            "5",
					ContainerName: "container1",
				},
			}

			kClientMock.adqConfig = []*kubeletclient.AdqConfigEntry{
				{
					Name: "container1",
					Ports: &kubeletclient.AdqPortMapEntry{
						LocalPorts: []string{
							"12345/TCP",
						},
						RemotePorts: []string{
							"54321/UDP",
						},
					},
				},
			}

			adqm = &netlinktc.NetlinkTcMock{}
			adqtcInit = adqTCInit

			err := CmdAdd(&args)

			Expect(err).ToNot(HaveOccurred())
			Expect(adqm.AddFilterReqests).To(HaveLen(4))

			Expect(reflect.ValueOf(adqm.AddFilterReqests[0].CreateFilterFunc).Pointer()).To(Equal(reflect.ValueOf(netlinktc.CreateIngressFlower).Pointer()))
			Expect(adqm.AddFilterReqests[0].Filter).To(Equal(netlinktc.AdqFilter{
				IpAddress:   ipnet.IP.To16(),
				IpProto:     netlinktc.StringToIpProto("TCP"),
				Tunnel:      netlinktc.TUNNELING_DISABLED,
				TC:          5,
				Dir:         netlinktc.DirectionLocal,
				PortValue:   12345,
				QueueNumber: 0,
				FilterPrio:  1,
			}))

			Expect(reflect.ValueOf(adqm.AddFilterReqests[1].CreateFilterFunc).Pointer()).To(Equal(reflect.ValueOf(netlinktc.CreateEgressFlower).Pointer()))
			Expect(adqm.AddFilterReqests[1].Filter).To(Equal(netlinktc.AdqFilter{
				IpAddress:   ipnet.IP.To16(),
				IpProto:     netlinktc.StringToIpProto("TCP"),
				Tunnel:      netlinktc.TUNNELING_DISABLED,
				TC:          5,
				Dir:         netlinktc.DirectionLocal,
				PortValue:   12345,
				QueueNumber: 0,
				FilterPrio:  1,
			}))

			Expect(reflect.ValueOf(adqm.AddFilterReqests[2].CreateFilterFunc).Pointer()).To(Equal(reflect.ValueOf(netlinktc.CreateIngressFlower).Pointer()))
			Expect(adqm.AddFilterReqests[2].Filter).To(Equal(netlinktc.AdqFilter{
				IpAddress:   ipnet.IP.To16(),
				IpProto:     netlinktc.StringToIpProto("UDP"),
				Tunnel:      netlinktc.TUNNELING_DISABLED,
				TC:          5,
				Dir:         netlinktc.DirectionRemote,
				PortValue:   54321,
				QueueNumber: 0,
				FilterPrio:  1,
			}))

			Expect(reflect.ValueOf(adqm.AddFilterReqests[3].CreateFilterFunc).Pointer()).To(Equal(reflect.ValueOf(netlinktc.CreateEgressFlower).Pointer()))
			Expect(adqm.AddFilterReqests[3].Filter).To(Equal(netlinktc.AdqFilter{
				IpAddress:   ipnet.IP.To16(),
				IpProto:     netlinktc.StringToIpProto("UDP"),
				Tunnel:      netlinktc.TUNNELING_DISABLED,
				TC:          5,
				Dir:         netlinktc.DirectionRemote,
				PortValue:   54321,
				QueueNumber: 0,
				FilterPrio:  1,
			}))
		})

		var _ = It("ADQ config contains ALL/TCP port value", func() {
			kClientMock = &kubeletClientMock{}
			kClientGetError = nil

			kClientMock.resourceMap = []*kubeletclient.ResourceInfo{
				{
					TC:            "5",
					ContainerName: "container1",
				},
			}

			kClientMock.adqConfig = []*kubeletclient.AdqConfigEntry{
				{
					Name: "container1",
					Ports: &kubeletclient.AdqPortMapEntry{
						LocalPorts: []string{
							"ALL/TCP",
						},
					},
				},
			}

			adqm = &netlinktc.NetlinkTcMock{}
			adqtcInit = adqTCInit

			err := CmdAdd(&args)

			Expect(err).ToNot(HaveOccurred())
			Expect(adqm.AddFilterReqests).To(HaveLen(2))

			Expect(reflect.ValueOf(adqm.AddFilterReqests[0].CreateFilterFunc).Pointer()).To(Equal(reflect.ValueOf(netlinktc.CreateIngressFlower).Pointer()))
			Expect(adqm.AddFilterReqests[0].Filter).To(Equal(netlinktc.AdqFilter{
				IpAddress:   ipnet.IP.To16(),
				IpProto:     netlinktc.StringToIpProto("TCP"),
				Tunnel:      netlinktc.TUNNELING_DISABLED,
				TC:          5,
				Dir:         netlinktc.DirectionLocal,
				PortValue:   0,
				QueueNumber: 0,
				FilterPrio:  1,
			}))

			Expect(reflect.ValueOf(adqm.AddFilterReqests[1].CreateFilterFunc).Pointer()).To(Equal(reflect.ValueOf(netlinktc.CreateEgressFlower).Pointer()))
			Expect(adqm.AddFilterReqests[1].Filter).To(Equal(netlinktc.AdqFilter{
				IpAddress:   ipnet.IP.To16(),
				IpProto:     netlinktc.StringToIpProto("TCP"),
				Tunnel:      netlinktc.TUNNELING_DISABLED,
				TC:          5,
				Dir:         netlinktc.DirectionLocal,
				PortValue:   0,
				QueueNumber: 0,
				FilterPrio:  1,
			}))

		})

		var _ = It("ADQ config does not define pods", func() {
			kClientMock = &kubeletClientMock{}
			kClientGetError = nil

			kClientMock.resourceMap = []*kubeletclient.ResourceInfo{
				{
					TC:            "5",
					ContainerName: "container1",
				},
			}

			adqm = &netlinktc.NetlinkTcMock{}
			adqtcInit = adqTCInit

			err := CmdAdd(&args)

			Expect(err).ToNot(HaveOccurred())
			Expect(adqm.AddFilterReqests).To(HaveLen(2))

			Expect(reflect.ValueOf(adqm.AddFilterReqests[0].CreateFilterFunc).Pointer()).To(Equal(reflect.ValueOf(netlinktc.CreateIngressFlower).Pointer()))
			Expect(adqm.AddFilterReqests[0].Filter).To(Equal(netlinktc.AdqFilter{
				IpAddress:   ipnet.IP.To16(),
				IpProto:     netlinktc.StringToIpProto("ALL"),
				Tunnel:      netlinktc.TUNNELING_DISABLED,
				TC:          5,
				Dir:         netlinktc.DirectionLocal,
				PortValue:   0,
				QueueNumber: 0,
				FilterPrio:  1,
			}))

			Expect(reflect.ValueOf(adqm.AddFilterReqests[1].CreateFilterFunc).Pointer()).To(Equal(reflect.ValueOf(netlinktc.CreateEgressFlower).Pointer()))
			Expect(adqm.AddFilterReqests[1].Filter).To(Equal(netlinktc.AdqFilter{
				IpAddress:   ipnet.IP.To16(),
				IpProto:     netlinktc.StringToIpProto("ALL"),
				Tunnel:      netlinktc.TUNNELING_DISABLED,
				TC:          5,
				Dir:         netlinktc.DirectionLocal,
				PortValue:   0,
				QueueNumber: 0,
				FilterPrio:  1,
			}))
		})
	})
})

var _ = Describe("CmdDel should return error if", func() {
	var _ = It("is called with invalid args", func() {
		args := skel.CmdArgs{
			Args: "someinvaliddata",
		}
		err := CmdDel(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Unable to load args"))
	})

	var _ = It("is called with invalid stdin data", func() {
		args := skel.CmdArgs{
			StdinData: []byte("someinvaliddata"),
		}
		err := CmdDel(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Loading network configuration unsuccessful"))
	})

	var _ = It("is not able to get container IP from args", func() {
		n := &adqConf{}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args := skel.CmdArgs{
			StdinData: j,
		}

		linkMock = &LinkMock{
			linkByNameErr: errors.New("netlink LinkByName error"),
		}

		getContainerIP = getContainerIPfromArgs
		linkByName = LinkByNameMock
		addrList = AddrListMock
		withNetNSPath = WithNetNSPathMock

		err = CmdDel(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("netlink LinkByName error"))

		linkMock = &LinkMock{
			linkByNameErr: nil,
			addrListErr:   errors.New("netlink AddrList error"),
		}

		err = CmdDel(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("netlink AddrList error"))
	})

	var _ = It("delTC returns an error", func() {
		adqm = &netlinktc.NetlinkTcMock{}
		adqtcInit = adqTCInit

		n := &adqConf{}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())
		args := skel.CmdArgs{
			IfName:    "eno1",
			StdinData: j,
		}

		ip := net.ParseIP("10.11.22.33")
		getContainerIP = func(*skel.CmdArgs) (net.IP, error) {
			return ip, nil
		}

		adqm.AdqTCInitError = errors.New("adqtcInit error")
		err = CmdDel(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("adqtcInit error"))

		adqm.AdqTCInitError = nil
		adqm.DelFlowerErr = errors.New("TCDelFlowerFilters error")
		err = CmdDel(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("TCDelFlowerFilters error"))
	})
})

var _ = Describe("CmdDel should return no error and call TCDelFilters() if", func() {
	var _ = It("is called with valid IP", func() {
		adqm = &netlinktc.NetlinkTcMock{}
		adqtcInit = adqTCInit

		n := &adqConf{}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())
		args := skel.CmdArgs{
			IfName:    "eno1",
			StdinData: j,
		}

		ip := net.ParseIP("10.11.22.33")
		getContainerIP = func(*skel.CmdArgs) (net.IP, error) {
			return ip, nil
		}

		err = CmdDel(&args)
		Expect(err).ToNot(HaveOccurred())
		Expect(adqm.DelFlowerRequests).To(HaveLen(1))
		Expect(adqm.DelFlowerRequests).To(ContainElement(ip))
	})
})

var _ = Describe("CmdCheck should return error if", func() {
	var _ = It("is called with invalid args", func() {
		args := skel.CmdArgs{
			Args: "someinvaliddata",
		}
		err := CmdCheck(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(`ARGS: invalid pair "someinvaliddata"`))
	})

	var _ = It("is called with invalid stdin data", func() {
		args := skel.CmdArgs{
			StdinData: []byte("someinvaliddata"),
		}
		err := CmdCheck(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Loading network configuration unsuccessful"))
	})

	var _ = It("is called with valid stdin data but is unable to read discovered one", func() {
		n := &adqConf{}

		oldDefaultNodeConfigPath := defaultNodeConfigPath

		defaultNodeConfigPath = "/someinvalidpath"

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args := skel.CmdArgs{
			StdinData: j,
		}
		err = CmdCheck(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Unable to read node config"))

		defaultNodeConfigPath = oldDefaultNodeConfigPath
	})

	var _ = It("CNIVersion is missing", func() {
		n := &adqConf{}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args := skel.CmdArgs{
			StdinData: j,
		}
		err = CmdCheck(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(`invalid version "": the version is empty`))
	})

	var _ = It("is called with missing RawPrevResult", func() {
		n := &adqConf{
			NetConf: types.NetConf{
				CNIVersion: "0.4.0",
			},
		}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args := skel.CmdArgs{
			StdinData: j,
		}
		err = CmdCheck(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Required prevResult missing"))
	})

	var _ = It("is not able to parse RawPrevResult", func() {
		nr := current.Result{
			CNIVersion: "0.4.0",
		}

		value := map[string]int{
			"someinvaliddata": 123,
		}
		rawResult := map[string]interface{}{
			"CNIVersion": value,
		}

		n := &adqConf{
			NetConf: types.NetConf{
				CNIVersion:    "0.4.0",
				PrevResult:    &nr,
				RawPrevResult: rawResult,
			},
		}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args := skel.CmdArgs{
			StdinData: j,
		}

		err = CmdCheck(&args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("could not parse prevResult"))
	})

	var _ = It("retrieved filters are empty and does not match to the requested", func() {
		getKubeletClient = GetKubeletClientMock
		_, ipnet, _ := net.ParseCIDR("10.123.123.1/24")
		prevRes := current.Result{
			CNIVersion: "0.4.0",
			IPs: []*current.IPConfig{
				{
					Version: "4",
					Address: *ipnet,
				},
			},
		}

		// convert struct to map[string]interface{}
		temp, err := json.Marshal(prevRes)
		Expect(err).ToNot(HaveOccurred())
		raw := make(map[string]interface{})
		err = json.Unmarshal(temp, &raw)
		Expect(err).ToNot(HaveOccurred())

		n := &adqConf{
			NetConf: types.NetConf{
				CNIVersion:    "0.4.0",
				PrevResult:    &prevRes,
				RawPrevResult: raw,
			},
		}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args := skel.CmdArgs{
			StdinData: j,
		}

		kClientMock = &kubeletClientMock{}
		kClientGetError = nil

		kClientMock.resourceMap = []*kubeletclient.ResourceInfo{
			{
				TC:            "5",
				ContainerName: "container1",
			},
		}

		kClientMock.adqConfig = []*kubeletclient.AdqConfigEntry{
			{
				Name: "container1",
				Ports: &kubeletclient.AdqPortMapEntry{
					LocalPorts: []string{
						"12345/TCP",
					},
					RemotePorts: []string{
						"4321/UDP",
					},
				},
			},
		}

		adqm = &netlinktc.NetlinkTcMock{}
		adqtcInit = adqTCInit

		err = CmdCheck(&args)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Cannot find filter on interface"))
	})
})

var _ = Describe("CmdCheck should return no error and call TCGetFilters() if", func() {
	var args skel.CmdArgs
	var ipnet *net.IPNet
	var _ = BeforeEach(func() {
		getKubeletClient = GetKubeletClientMock

		_, ipnet, _ = net.ParseCIDR("10.123.123.1/24")
		prevRes := current.Result{
			CNIVersion: "0.4.0",
			IPs: []*current.IPConfig{
				{
					Version: "4",
					Address: *ipnet,
				},
			},
		}

		// convert struct to map[string]interface{}
		temp, err := json.Marshal(prevRes)
		Expect(err).ToNot(HaveOccurred())
		raw := make(map[string]interface{})
		err = json.Unmarshal(temp, &raw)
		Expect(err).ToNot(HaveOccurred())

		n := &adqConf{
			NetConf: types.NetConf{
				CNIVersion:    "0.4.0",
				PrevResult:    &prevRes,
				RawPrevResult: raw,
			},
		}

		j, err := json.Marshal(n)
		Expect(err).ToNot(HaveOccurred())

		args = skel.CmdArgs{
			StdinData: j,
		}
	})

	var _ = Context("is able to retrive valid data from kubeletclient", func() {
		var _ = It("ADQ config contains ports", func() {
			kClientMock = &kubeletClientMock{}
			kClientGetError = nil

			kClientMock.resourceMap = []*kubeletclient.ResourceInfo{
				{
					TC:            "5",
					ContainerName: "container1",
				},
			}

			kClientMock.adqConfig = []*kubeletclient.AdqConfigEntry{
				{
					Name: "container1",
					Ports: &kubeletclient.AdqPortMapEntry{
						LocalPorts: []string{
							"12345/TCP",
						},
						RemotePorts: []string{
							"1234/TCP",
						},
					},
				},
			}

			hwtc, _ := netlinktc.GetHWClassID(uint32(5))
			adqm = &netlinktc.NetlinkTcMock{}
			adqm.GetFlowerFiltersErr = nil

			otherIp := net.ParseIP("192.168.1.1")

			adqm.GetFlowerFilters = []*netlink.Flower{

				{
					FilterAttrs: netlink.FilterAttrs{},
					DestIP:      ipnet.IP,
					IPProto:     uint8(netlinktc.StringToIpProto("TCP")),
					TcpDestPort: 12345,
					ClassID:     hwtc,
				},

				{
					FilterAttrs: netlink.FilterAttrs{},
					DestIP:      ipnet.IP,
					IPProto:     uint8(netlinktc.StringToIpProto("TCP")),
					TcpSrcPort:  1234,
					ClassID:     hwtc,
				},

				{
					FilterAttrs: netlink.FilterAttrs{},
					ClassID:     0,
				},

				{
					FilterAttrs: netlink.FilterAttrs{},
					ClassID:     123,
				},

				{
					FilterAttrs: netlink.FilterAttrs{},
					DestIP:      otherIp,
					IPProto:     uint8(netlinktc.StringToIpProto("TCP")),
					ClassID:     hwtc,
				},

				{
					FilterAttrs: netlink.FilterAttrs{},
					DestIP:      ipnet.IP,
					IPProto:     uint8(netlinktc.StringToIpProto("UDP")),
					UdpSrcPort:  1234,
					ClassID:     hwtc,
				},
			}

			adqtcInit = adqTCInit

			err := CmdCheck(&args)
			Expect(err).ToNot(HaveOccurred())
		})
	})
})

var _ = Describe("validateTcSettings should return error if", func() {
	var _ = It("adqtcInit returns error", func() {
		adqm = &netlinktc.NetlinkTcMock{}
		adqtcInit = adqTCInit
		adqm.AdqTCInitError = errors.New("adqtcInit error")

		err := validateTcSettings("", "", net.ParseIP("192.168.1.123"), "", netlinktc.DirectionLocal, 123)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("adqtcInit error"))
	})

	var _ = It("TCGetFlowerFilters returns error", func() {
		adqm = &netlinktc.NetlinkTcMock{}
		adqtcInit = adqTCInit
		adqm.GetFlowerFiltersErr = errors.New("TCGetFlowerFilters error")

		err := validateTcSettings("", "", net.ParseIP("192.168.1.123"), "", netlinktc.DirectionLocal, 123)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("TCGetFlowerFilters error"))
	})

	var _ = It("TC value is invalid", func() {
		adqm = &netlinktc.NetlinkTcMock{}
		adqtcInit = adqTCInit

		err := validateTcSettings("", "invalidtcvalue", net.ParseIP("192.168.1.123"), "", netlinktc.DirectionLocal, 123)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(`strconv.ParseUint: parsing "invalidtcvalue": invalid syntax`))
	})

	var _ = It("TC value exceeds the max value", func() {
		adqm = &netlinktc.NetlinkTcMock{}
		adqtcInit = adqTCInit

		tcval := 0x0010
		err := validateTcSettings("", strconv.Itoa(int(tcval)), net.ParseIP("192.168.1.123"), "", netlinktc.DirectionLocal, 123)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("provided hw_tc:16 exceeds max 0x000F"))
	})
})
