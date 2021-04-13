// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation

package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/intel/adq-device-plugin/pkg/netlinktc"
	"github.com/intel/intel-device-plugins-for-kubernetes/pkg/deviceplugin"
	"github.com/intel/intel-device-plugins-for-kubernetes/pkg/topology"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

func TestDevicePlugin(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ADQ device plugin Test Suite")
}

var (
	chekDone bool
)

type notifierMock struct {
	expecteddt deviceplugin.DeviceTree
}

func (n *notifierMock) Notify(dt deviceplugin.DeviceTree) {
	Eventually(dt, "5s").Should(Equal(n.expecteddt))
	chekDone = true
}

var _ = Describe("getTCCalues should return valid values if", func() {
	adqm := &netlinktc.NetlinkTcMock{}
	adqm.NumTC = 3
	adqm.SharedTCNum = 5
	adqm.StartQ = 55
	adqm.StopQ = 66
	adqm.SharedTCErr = nil
	adqm.StartStopErr = nil

	var _ = It("gets mode set to adq-single", func() {
		adqtcInit = func(ifname string, virtual bool) (netlinktc.NetlinkTc, error) {
			adqm.InitMaster = ifname
			return adqm, adqm.AdqTCInitError
		}

		numTC, sharedTC, startQ, stopQ, err := getTCValues("eth123", "adq-single")
		Expect(err).ToNot(HaveOccurred())
		Expect(numTC).To(Equal(0))
		Expect(sharedTC).To(Equal(int(adqm.SharedTCNum)))
		Expect(startQ).To(Equal(int(adqm.StartQ)))
		Expect(stopQ).To(Equal(int(adqm.StopQ - 1)))

	})

	var _ = It("gets mode set to adq", func() {
		adqtcInit = func(ifname string, virtual bool) (netlinktc.NetlinkTc, error) {
			adqm.InitMaster = ifname
			return adqm, adqm.AdqTCInitError
		}
		numTC, sharedTC, startQ, stopQ, err := getTCValues("eth123", "adq")
		Expect(err).ToNot(HaveOccurred())
		Expect(numTC).To(Equal(int(adqm.NumTC)))
		Expect(sharedTC).To(Equal(-1))
		Expect(startQ).To(Equal(0))
		Expect(stopQ).To(Equal(-1))

	})

	var _ = It("gets mode set to mixed", func() {
		adqtcInit = func(ifname string, virtual bool) (netlinktc.NetlinkTc, error) {
			adqm.InitMaster = ifname
			return adqm, adqm.AdqTCInitError
		}
		numTC, sharedTC, startQ, stopQ, err := getTCValues("eth123", "mixed")
		Expect(err).ToNot(HaveOccurred())
		Expect(numTC).To(Equal(int(adqm.NumTC)))
		Expect(sharedTC).To(Equal(int(adqm.SharedTCNum)))
		Expect(startQ).To(Equal(int(adqm.StartQ)))
		Expect(stopQ).To(Equal(int(adqm.StopQ - 1)))
	})
})

var _ = Describe("getTCValues should return error if", func() {
	adqm := netlinktc.NetlinkTcMock{}

	var _ = It("recieves error from GetSharedTC", func() {
		adqm.SharedTCErr = errors.New("some get shared tc error")
		adqtcInit = func(ifname string, virtual bool) (netlinktc.NetlinkTc, error) {
			adqm.InitMaster = ifname
			return &adqm, adqm.AdqTCInitError
		}
		_, _, _, _, err := getTCValues("eth123", "mixed")
		Expect(err).To(HaveOccurred())
	})
	var _ = It("recieves error from TCGetStartStopQ", func() {
		adqm.StartStopErr = errors.New("some get start stop error")
		adqtcInit = func(ifname string, virtual bool) (netlinktc.NetlinkTc, error) {
			adqm.InitMaster = ifname
			return &adqm, adqm.AdqTCInitError
		}
		_, _, _, _, err := getTCValues("eth123", "mixed")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("scan() should return valid device tree", func() {
	topologyInfo := &pluginapi.TopologyInfo{
		Nodes: []*pluginapi.NUMANode{
			{
				ID: 1,
			},
		},
	}

	topologyHints := make(topology.Hints)
	hint := topology.Hint{
		Provider: "/sys/devices/somedevice",
		NUMAs:    "1",
	}

	topologyHints[hint.Provider] = hint

	newTopologyHints = func(devPath string) (hints topology.Hints, err error) {
		return topologyHints, nil
	}

	var _ = It("is configured to adq shared mode", func() {
		getTopologyInfo = GetTopologyInfo
		dp := &devicePlugin{
			numTC:      0,
			sharedTC:   2,
			startQueue: 55,
			stopQueue:  56,
		}
		dt, err := dp.scan()
		Expect(err).ToNot(HaveOccurred())
		Expect(dt).To(HaveLen(1))
		Expect(dt).To(HaveKey(deviceTypeSharedQ))

		Expect(dt[deviceTypeSharedQ]).To(HaveLen(2))
		Expect(dt[deviceTypeSharedQ]).To(HaveKey("55"))

		Expect(dt[deviceTypeSharedQ]["55"]).To(
			Equal(deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy,
				[]pluginapi.DeviceSpec{}, []pluginapi.Mount{}, map[string]string{}, map[string]string{}, topologyInfo)))

		Expect(dt[deviceTypeSharedQ]).To(HaveKey("56"))
		Expect(dt[deviceTypeSharedQ]["56"]).To(
			Equal(deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy,
				[]pluginapi.DeviceSpec{}, []pluginapi.Mount{}, map[string]string{}, map[string]string{}, topologyInfo)))

	})
	var _ = It("is configured to adq exclusive mode (TC0 is reserved)", func() {
		getTopologyInfo = GetTopologyInfo
		dp := &devicePlugin{
			numTC:      3,
			sharedTC:   -1,
			startQueue: 0,
			stopQueue:  -1,
		}
		dt, err := dp.scan()
		Expect(err).ToNot(HaveOccurred())
		Expect(dt).To(HaveLen(1))
		Expect(dt).To(HaveKey(deviceTypeExclusiveQ))

		Expect(dt[deviceTypeExclusiveQ]).To(HaveLen(2))
		Expect(dt[deviceTypeExclusiveQ]).To(HaveKey("1"))
		Expect(dt[deviceTypeExclusiveQ]["1"]).To(
			Equal(deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy,
				[]pluginapi.DeviceSpec{}, []pluginapi.Mount{}, map[string]string{}, map[string]string{}, topologyInfo)))
		Expect(dt[deviceTypeExclusiveQ]).To(HaveKey("2"))
		Expect(dt[deviceTypeExclusiveQ]["2"]).To(
			Equal(deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy,
				[]pluginapi.DeviceSpec{}, []pluginapi.Mount{}, map[string]string{}, map[string]string{}, topologyInfo)))

	})
	var _ = It("is configured to adq mixed mode", func() {
		getTopologyInfo = GetTopologyInfo
		dp := &devicePlugin{
			numTC:      3,
			sharedTC:   2,
			startQueue: 55,
			stopQueue:  56,
		}
		dt, err := dp.scan()
		Expect(err).ToNot(HaveOccurred())
		Expect(dt).To(HaveLen(2))
		Expect(dt).To(HaveKey(deviceTypeExclusiveQ))

		Expect(dt[deviceTypeExclusiveQ]).To(HaveLen(1))
		Expect(dt[deviceTypeExclusiveQ]).To(HaveKey("1"))
		Expect(dt[deviceTypeExclusiveQ]["1"]).To(
			Equal(deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy,
				[]pluginapi.DeviceSpec{}, []pluginapi.Mount{}, map[string]string{}, map[string]string{}, topologyInfo)))

		Expect(dt[deviceTypeSharedQ]).To(HaveLen(2))
		Expect(dt[deviceTypeSharedQ]).To(HaveKey("55"))
		Expect(dt[deviceTypeSharedQ]["55"]).To(
			Equal(deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy,
				[]pluginapi.DeviceSpec{}, []pluginapi.Mount{}, map[string]string{}, map[string]string{}, topologyInfo)))
		Expect(dt[deviceTypeSharedQ]).To(HaveKey("56"))
		Expect(dt[deviceTypeSharedQ]["56"]).To(
			Equal(deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy,
				[]pluginapi.DeviceSpec{}, []pluginapi.Mount{}, map[string]string{}, map[string]string{}, topologyInfo)))
	})

	var _ = It("is configured to adq mixed mode but is unable to get topology info", func() {
		getTopologyInfo = func(devs string) (*pluginapi.TopologyInfo, error) {
			return nil, errors.New("Get topology error")
		}

		dp := &devicePlugin{
			numTC:      3,
			sharedTC:   2,
			startQueue: 55,
			stopQueue:  56,
		}
		dt, err := dp.scan()
		Expect(err).ToNot(HaveOccurred())
		Expect(dt).To(HaveLen(2))
		Expect(dt).To(HaveKey(deviceTypeExclusiveQ))

		Expect(dt[deviceTypeExclusiveQ]).To(HaveLen(1))
		Expect(dt[deviceTypeExclusiveQ]).To(HaveKey("1"))
		Expect(dt[deviceTypeExclusiveQ]["1"]).To(
			Equal(deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy,
				[]pluginapi.DeviceSpec{}, []pluginapi.Mount{}, map[string]string{}, map[string]string{}, nil)))

		Expect(dt[deviceTypeSharedQ]).To(HaveLen(2))
		Expect(dt[deviceTypeSharedQ]).To(HaveKey("55"))
		Expect(dt[deviceTypeSharedQ]["55"]).To(
			Equal(deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy,
				[]pluginapi.DeviceSpec{}, []pluginapi.Mount{}, map[string]string{}, map[string]string{}, nil)))
		Expect(dt[deviceTypeSharedQ]).To(HaveKey("56"))
		Expect(dt[deviceTypeSharedQ]["56"]).To(
			Equal(deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy,
				[]pluginapi.DeviceSpec{}, []pluginapi.Mount{}, map[string]string{}, map[string]string{}, nil)))
	})
})

var _ = Describe("PostAllocate() should fill AllocateResponse entries with master interface name if", func() {
	var _ = It("is provided", func() {
		dp := &devicePlugin{
			master: "eno123",
		}

		response := &pluginapi.AllocateResponse{
			ContainerResponses: []*pluginapi.ContainerAllocateResponse{
				{},
				{},
			},
		}
		_ = dp.PostAllocate(response)
		Expect(response.GetContainerResponses()).To(HaveLen(2))
		Expect(response.GetContainerResponses()[0].Annotations).To(HaveKey(annotationName))
		Expect(response.GetContainerResponses()[0].Annotations[annotationName]).To(Equal(dp.master))
		Expect(response.GetContainerResponses()[1].Annotations).To(HaveKey(annotationName))
		Expect(response.GetContainerResponses()[1].Annotations[annotationName]).To(Equal(dp.master))
	})
})

var _ = Describe("newDevicePlugin should ", func() {
	var _ = It("return valid devicePlugin for valid TC values", func() {
		adqm := &netlinktc.NetlinkTcMock{}
		adqm.NumTC = 3
		adqm.SharedTCNum = 5
		adqm.StartQ = 55
		adqm.StopQ = 66
		adqm.SharedTCErr = nil
		adqm.StartStopErr = nil
		adqtcInit = func(ifname string, virtual bool) (netlinktc.NetlinkTc, error) {
			adqm.InitMaster = ifname
			return adqm, adqm.AdqTCInitError
		}
		pd, err := newDevicePlugin("eth123", "mixed", 123456)
		Expect(err).ToNot(HaveOccurred())
		Expect(pd).ToNot(BeNil())
		Expect(pd.master).To(Equal("eth123"))
	})

	var _ = It("return error when cannot get TC values", func() {
		adqm := &netlinktc.NetlinkTcMock{}
		adqm.SharedTCErr = errors.New("cannot get TC values")
		adqtcInit = func(ifname string, virtual bool) (netlinktc.NetlinkTc, error) {
			adqm.InitMaster = ifname
			return adqm, adqm.AdqTCInitError
		}
		pd, err := newDevicePlugin("eth123", "mixed", 123456)
		Expect(err).To(HaveOccurred())
		Expect(pd).To(BeNil())
	})
})

var _ = Describe("parseFlags should", func() {
	const nodeConfigJ = `
	{                                                                                                                                                                                                                                                                                                                                
		"EgressMode": "skbedit",                                                                                                                                                                                                                                                                                                     
		"FilterPrio": 1,                                                                                                                                                                                                                                                                                                             
		"Globals": {                                                                                                                                                                                                                                                                                                                 
			"Dev": "ens801f0"                                                                                                                                                                                                                                                                                                      
		}
	}
	`

	f, err := ioutil.TempFile("/tmp", "")
	Expect(err).NotTo(HaveOccurred())

	err = os.WriteFile(f.Name(), []byte(nodeConfigJ), 0644)
	Expect(err).NotTo(HaveOccurred())

	defaultNodeConfigPath = f.Name()

	var _ = Context("return an error", func() {
		var _ = It("if -h is passed as argument", func() {
			_, _, err := parseFlags("prog", []string{"-h"})
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(flag.ErrHelp))
		})

		var _ = It("if reconcile period is lower than 0", func() {
			_, _, err := parseFlags("prog", []string{"-reconcile-period", "-3s"})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("reconcile period must be greater than 0"))
		})

		var _ = It("if there is a problem with getting TC", func() {
			adqm := &netlinktc.NetlinkTcMock{}
			adqtcInit = func(ifname string, virtual bool) (netlinktc.NetlinkTc, error) {
				adqm.InitMaster = ifname
				return adqm, adqm.AdqTCInitError
			}
			adqm.AdqTCInitError = errors.New("adqtc init error")
			_, _, err := parseFlags("prog", []string{"-reconcile-period", "3s"})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("adqtc init error"))
		})
	})

	var _ = Context("return valid devicePlugin", func() {
		var _ = It("for valid input data", func() {

			adqm := &netlinktc.NetlinkTcMock{}
			adqm.NumTC = 3
			adqm.SharedTCNum = 5
			adqm.StartQ = 55
			adqm.StopQ = 66
			adqm.SharedTCErr = nil
			adqm.StartStopErr = nil
			adqtcInit = func(ifname string, virtual bool) (netlinktc.NetlinkTc, error) {
				adqm.InitMaster = ifname
				return adqm, adqm.AdqTCInitError
			}
			d, err := time.ParseDuration("3s")
			Expect(err).ToNot(HaveOccurred())
			dp, _, err := parseFlags("prog", []string{"-reconcile-period", "3s"})
			Expect(err).ToNot(HaveOccurred())
			Expect(dp).ToNot(BeNil())
			Expect(dp.master).To(Equal("ens801f0"))
			Expect(dp.reconcilePeriod).To(Equal(d))
			Expect(dp.numTC).To(Equal(3))
			Expect(dp.sharedTC).To(Equal(5))
			Expect(dp.startQueue).To(Equal(55))
			Expect(dp.stopQueue).To(Equal(65))
		})
	})
})

var _ = Describe("Scan should", func() {
	var _ = It("notify valid DeviceTree", func() {
		d, err := time.ParseDuration("500ms")
		Expect(err).ToNot(HaveOccurred())
		topologyInfo := &pluginapi.TopologyInfo{
			Nodes: []*pluginapi.NUMANode{
				{
					ID: 1,
				},
			},
		}

		getTopologyInfo = func(devs string) (*pluginapi.TopologyInfo, error) {
			return topologyInfo, nil
		}

		notifierMock := &notifierMock{}
		notifierMock.expecteddt = deviceplugin.NewDeviceTree()
		TC := fmt.Sprintf("%d", 55)
		envs := map[string]string{}
		annotations := map[string]string{}
		nodes := []pluginapi.DeviceSpec{}
		mount := []pluginapi.Mount{}
		notifierMock.expecteddt.AddDevice(deviceTypeSharedQ, TC,
			deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy, nodes, mount, envs, annotations, topologyInfo))
		TC = fmt.Sprintf("%d", 56)
		notifierMock.expecteddt.AddDevice(deviceTypeSharedQ, TC,
			deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy, nodes, mount, envs, annotations, topologyInfo))
		TC = fmt.Sprintf("%d", 1)
		notifierMock.expecteddt.AddDevice(deviceTypeExclusiveQ, TC,
			deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy, nodes, mount, envs, annotations, topologyInfo))
		dp := &devicePlugin{
			numTC:           3,
			sharedTC:        2,
			startQueue:      55,
			stopQueue:       56,
			reconcilePeriod: d,
		}
		chekDone = false
		go func() {
			defer GinkgoRecover()
			err := dp.Scan(notifierMock)
			Expect(err).ToNot(HaveOccurred())
		}()
		Eventually(func() bool {
			return chekDone
		}, "3s").Should(BeTrue())
		// validation in Notifier Notify function

		getTopologyInfo = func(devs string) (*pluginapi.TopologyInfo, error) {
			return nil, errors.New("stop Scan loop")
		}
	})
})
