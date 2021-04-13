// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation

package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/intel/adq-device-plugin/pkg/nodeconfigtypes"
	. "github.com/intel/adq-device-plugin/pkg/nodeconfigtypes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMain(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ADQ Node Config Test Suite")
}

var (
	getFakeNetInterfacesErr error
	fakeNetInterfaces       []net.Interface
)

func getFakeNetInterfaces() ([]net.Interface, error) {
	return fakeNetInterfaces, getFakeNetInterfacesErr
}

var _ = Describe("getNode should return error if", func() {
	var _ = It("invalid kubeconfigpath is used", func() {
		defaultADQKubeConfigPath = "/someinvalidpath"
		nl, err := getNode("node1")
		Expect(err).To(HaveOccurred())
		Expect(nl).To(BeNil())
	})
})

var _ = Describe("getIfaceName should return error if", func() {
	var _ = It("empty node list is used", func() {
		name, err := getIfaceName(nil)
		Expect(err).To(HaveOccurred())
		Expect(name).To(BeEmpty())
	})

	var _ = It("NodeInternalIP is empty", func() {
		node := v1.Node{
			Status: v1.NodeStatus{
				Addresses: []v1.NodeAddress{
					{
						Type:    v1.NodeInternalIP,
						Address: "",
					},
				},
			},
		}

		name, err := getIfaceName(&node)
		Expect(err).To(HaveOccurred())
		Expect(name).To(BeEmpty())
	})

	var _ = It("getNetInterfaces returns error", func() {
		node := v1.Node{
			Status: v1.NodeStatus{
				Addresses: []v1.NodeAddress{
					{
						Type:    v1.NodeInternalIP,
						Address: "192.168.1.10",
					},
				},
			},
		}

		getFakeNetInterfacesErr = errors.New("get net interfaces error")
		getNetInterfaces = getFakeNetInterfaces

		name, err := getIfaceName(&node)
		Expect(err).To(HaveOccurred())
		Expect(name).To(BeEmpty())
	})

	var _ = It("master interface is not found", func() {
		node := v1.Node{
			Status: v1.NodeStatus{
				Addresses: []v1.NodeAddress{
					{
						Type:    v1.NodeInternalIP,
						Address: "192.168.1.10",
					},
				},
			},
		}

		getFakeNetInterfacesErr = nil
		getNetInterfaces = getFakeNetInterfaces

		name, err := getIfaceName(&node)
		Expect(err).To(HaveOccurred())
		Expect(name).To(BeEmpty())
	})
})

var _ = It("getIfaceName should return valid master interface name", func() {
	node := v1.Node{
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{
				{
					Type:    v1.NodeInternalIP,
					Address: "192.168.1.10",
				},
			},
		},
	}

	getFakeNetInterfacesErr = nil
	fakeNetInterfaces = []net.Interface{
		{
			Name: "eth1",
		},
		{
			Name:         "eth2",
			HardwareAddr: net.HardwareAddr("xxxxx"),
			Index:        10,
		},
	}
	getNetInterfaces = getFakeNetInterfaces

	name, err := getIfaceName(&node)
	Expect(err).To(HaveOccurred())
	Expect(name).To(BeEmpty())
})

var _ = Describe("getMatchingADQNodeConfig should return error if", func() {
	node := v1.Node{
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{
				{
					Type:    v1.NodeInternalIP,
					Address: "192.168.1.10",
				},
			},
		},
	}

	var tempConfigDir string

	var _ = BeforeEach(func() {
		var err error
		tempConfigDir, err = os.MkdirTemp("", "fakeconfigmapdir")
		Expect(err).NotTo(HaveOccurred())
	})

	var _ = AfterEach(func() {
		err := os.RemoveAll(tempConfigDir)
		Expect(err).NotTo(HaveOccurred())
	})

	var _ = It("is not able to open cluster config file", func() {
		cfg, err := getMatchingADQNodeConfig(defaultADQClusterConfigPath, &node)
		Expect(err).To(HaveOccurred())
		Expect(cfg).To(BeNil())
	})

	var _ = It("is not able to unmarshal cluster config file", func() {
		p := filepath.Join(tempConfigDir, "adq-cluster-config.json")

		invalidClusterConfig := `
		{
			"NodeConfigs": [
				{
					"Labels": {
					"missing_closing": "}"
				},
				"PollMode": "busypoll",
				"ResetCPUxps": false,
				"Queues": [32, 32]

			]
		}
		`

		b := []byte(invalidClusterConfig)
		err := os.WriteFile(p, b, 0777)
		Expect(err).ToNot(HaveOccurred())

		defaultADQClusterConfigPath = p

		cfg, err := getMatchingADQNodeConfig(defaultADQClusterConfigPath, &node)
		Expect(err).To(HaveOccurred())
		Expect(cfg).To(BeNil())
	})
})

var _ = Describe("getMatchingADQNodeConfig should return no error if", func() {
	clusterConfigA := `
	{
		"NodeConfigs": [
		  {
		    "Labels": {
		      "labelA": "A"
		    },
		    "EgressMode": "netprio"
		  }
		]
	      }
	`

	clusterConfigB := `
	{
		"NodeConfigs": [
		  {
		    "Labels": {
	              "labelA": "A",
		      "labelB": "B"
		    },
		    "EgressMode": "skbedit"
		  }
		]
	      }
	`
	var tempConfigDir string

	var _ = BeforeEach(func() {
		var err error
		tempConfigDir, err = os.MkdirTemp("", "fakeconfigmapdir")
		Expect(err).NotTo(HaveOccurred())
	})

	var _ = AfterEach(func() {
		err := os.RemoveAll(tempConfigDir)
		Expect(err).NotTo(HaveOccurred())
	})

	var _ = It("node labels does not match any config", func() {

		//nodeLabels := make(map[string]string)
		node := v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"some": "label",
				},
			},
		}

		p := filepath.Join(tempConfigDir, "adq-cluster-config.json")
		b := []byte(clusterConfigA)
		err := os.WriteFile(p, b, 0777)
		Expect(err).ToNot(HaveOccurred())

		defaultADQClusterConfigPath = p

		cfg, err := getMatchingADQNodeConfig(defaultADQClusterConfigPath, &node)
		Expect(err).ToNot(HaveOccurred())
		Expect(cfg).To(BeNil())

		_ = clusterConfigB
	})

	var _ = It("node labels does not match all required labels in config", func() {
		node := v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"labelA": "A",
				},
			},
		}

		p := filepath.Join(tempConfigDir, "adq-cluster-config.json")
		b := []byte(clusterConfigB)
		err := os.WriteFile(p, b, 0777)
		Expect(err).ToNot(HaveOccurred())

		defaultADQClusterConfigPath = p

		cfg, err := getMatchingADQNodeConfig(defaultADQClusterConfigPath, &node)
		Expect(err).ToNot(HaveOccurred())
		Expect(cfg).To(BeNil())

		_ = clusterConfigB
	})

	var _ = It("node labels does match all required labels in config", func() {
		node := v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"labelB": "B",
					"labelA": "A",
				},
			},
		}

		p := filepath.Join(tempConfigDir, "adq-cluster-config.json")
		b := []byte(clusterConfigB)
		err := os.WriteFile(p, b, 0777)
		Expect(err).ToNot(HaveOccurred())

		defaultADQClusterConfigPath = p

		cfg, err := getMatchingADQNodeConfig(defaultADQClusterConfigPath, &node)
		Expect(err).ToNot(HaveOccurred())
		Expect(cfg).ToNot(BeNil())

		Expect(cfg.EgressMode).To(Equal("skbedit"))

	})
})

var _ = Describe("getNodeConfig should return error if", func() {

	node := v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"labelA": "A",
			},
		},
	}
	tempConfigDir, err := os.MkdirTemp("", "fakeconfigmapdir")
	Expect(err).ToNot(HaveOccurred())

	var _ = It("is unable to parse node config json", func() {
		invalidClusterConfig := `
		{
			"NodeConfigs": [
			{
				"Labels": {
					"labelA": "A"
			},
			}

		}
		`
		p := filepath.Join(tempConfigDir, "adq-cluster-config.json")
		b := []byte(invalidClusterConfig)
		err = os.WriteFile(p, b, 0777)
		Expect(err).ToNot(HaveOccurred())

		adqsetup, ifaceEgress, err := getNodeConfig(&node, "someEth", p)

		Expect(err).To(HaveOccurred())
		Expect(adqsetup).To(BeEmpty())
		Expect(ifaceEgress).To(BeEmpty())
	})

	var _ = It("node config is empty", func() {
		clusterConfig := `
		{
			"NodeConfigs": []
		}
		`

		p := filepath.Join(tempConfigDir, "adq-cluster-config.json")
		b := []byte(clusterConfig)
		err = os.WriteFile(p, b, 0777)
		Expect(err).ToNot(HaveOccurred())

		adqsetup, ifaceEgress, err := getNodeConfig(&node, "someEth", p)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Node config is empty"))
		Expect(adqsetup).To(BeEmpty())
		Expect(ifaceEgress).To(BeEmpty())
	})
})

var _ = Describe("getNodeConfig should return valid node configuration string if", func() {
	node := v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"labelA": "A",
			},
		},
	}
	tempConfigDir, err := os.MkdirTemp("", "fakeconfigmapdir")
	Expect(err).ToNot(HaveOccurred())

	var _ = It("masterIface and valid node config object is passed", func() {
		clusterConfig := `
		{
			"NodeConfigs": [
				{
				"Labels": {
					"labelA": "A"
				},
				"EgressMode": "skbedit",
				"FilterPrio": 1,
				"Globals": {
					"Dev": "eth123",
					"Queues": 16,
					"Busypoll": 10000,
					"Txadapt": false,
					"Txusecs": 0,
					"Rxadapt": false,
					"Rxusecs": 500
				},
				"TrafficClass": [
						{ 
							"Queues": 4
						},
						{ 
							"Queues": 4
						},
						{ 
							"Queues": 4
						},
						{ 
							"Queues": 4
						},
						{ 
							"Queues": 32,
							"Mode": "shared"
						}
					]
				}
			]
		}
		`

		p := filepath.Join(tempConfigDir, "adq-cluster-config.json")
		b := []byte(clusterConfig)
		err = os.WriteFile(p, b, 0777)
		Expect(err).ToNot(HaveOccurred())

		adqsetup, ifaceEgress, err := getNodeConfig(&node, "eth0", p)
		Expect(err).ToNot(HaveOccurred())
		Expect(adqsetup).ToNot(BeEmpty())
		Expect(ifaceEgress).ToNot(BeEmpty())

		var nc nodeconfigtypes.AdqNodeConfig
		err = json.Unmarshal([]byte(ifaceEgress), &nc)
		Expect(err).ToNot(HaveOccurred())

		Expect(nc.Globals.Dev).To(Equal("eth123"))
		Expect(nc.EgressMode).To(Equal("skbedit"))

		Expect(adqsetup).To(ContainSubstring("[globals]\nbusypoll = 10000\nbusyread = 0\ndev = eth123\nqueues = 16\ntxadapt = off\nrxadapt = off\nrxusecs = 500"))
		Expect(adqsetup).To(ContainSubstring("[adqTC0]\nmode = exclusive\nqueues = 4"))
		Expect(adqsetup).To(ContainSubstring("[adqTC1]\nmode = exclusive\nqueues = 4"))
		Expect(adqsetup).To(ContainSubstring("[adqTC2]\nmode = exclusive\nqueues = 4"))
		Expect(adqsetup).To(ContainSubstring("[adqTC3]\nmode = exclusive\nqueues = 4"))
		Expect(adqsetup).To(ContainSubstring("[adqTC4]\nmode = shared\nqueues = 32"))

	})
})

var _ = Describe("validateNodeConfig should return error if", func() {
	var _ = It("node config is nil", func() {
		err := validateNodeConfig(nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Node config is empty"))
	})

	var _ = It("Node config has no labels specified", func() {
		adqc := AdqNodeConfig{
			Labels:     map[string]string{},
			EgressMode: "skbedit",
			Globals: GlobalsConfig{
				Dev:    "eth123",
				Queues: 16,
			},
			TrafficClass: []TrafficClassConfig{
				{
					Queues: 4,
				},
			},
		}

		err := validateNodeConfig(&adqc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Node config has no labels specified"))
	})

	var _ = It("Node config has invalid egress mode", func() {
		adqc := AdqNodeConfig{
			Labels: map[string]string{
				"label": "value",
			},
			EgressMode: "invalidegressmode",
			FilterPrio: 1,
			Globals: GlobalsConfig{
				Dev:    "eth123",
				Queues: 16,
			},
			TrafficClass: []TrafficClassConfig{
				{
					Queues: 4,
				},
			},
		}

		err := validateNodeConfig(&adqc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Invalid egress mode: invalidegressmode - supported: netprio or skbedit"))
	})

	var _ = It("Node config has Rxadapt enabled when Rxusecs is set", func() {
		adqc := AdqNodeConfig{
			Labels: map[string]string{
				"label": "value",
			},
			EgressMode: "skbedit",
			FilterPrio: 1,
			Globals: GlobalsConfig{
				Dev:     "eth123",
				Queues:  16,
				Rxadapt: true,
				Rxusecs: 50,
			},
			TrafficClass: []TrafficClassConfig{
				{
					Queues: 4,
				},
			},
		}

		err := validateNodeConfig(&adqc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("If Rxusecs is set Rxadapt must be turned off"))
	})

	var _ = It("Node config has Txadapt enabled when Txusecs is set", func() {
		adqc := AdqNodeConfig{
			Labels: map[string]string{
				"label": "value",
			},
			EgressMode: "skbedit",
			FilterPrio: 1,
			Globals: GlobalsConfig{
				Dev:     "eth123",
				Queues:  16,
				Txadapt: true,
				Txusecs: 50,
			},
			TrafficClass: []TrafficClassConfig{
				{
					Queues: 4,
				},
			},
		}

		err := validateNodeConfig(&adqc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("If Txusecs is set Txadapt must be turned off"))
	})

	var _ = It("Node config has invalid Globals.Cpus value", func() {
		adqc := AdqNodeConfig{
			Labels: map[string]string{
				"label": "value",
			},
			EgressMode: "skbedit",
			FilterPrio: 1,
			Globals: GlobalsConfig{
				Dev:    "eth123",
				Queues: 16,
				Cpus:   "abc",
			},
			TrafficClass: []TrafficClassConfig{
				{
					Queues: 4,
				},
			},
		}

		err := validateNodeConfig(&adqc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Invalid Globals.Cpus value: abc - must be an integer list or auto"))
	})

	var _ = It("Node config has invalid Globals.Numa value", func() {
		adqc := AdqNodeConfig{
			Labels: map[string]string{
				"label": "value",
			},
			EgressMode: "skbedit",
			FilterPrio: 1,
			Globals: GlobalsConfig{
				Dev:    "eth123",
				Queues: 16,
				Numa:   "abc",
			},
			TrafficClass: []TrafficClassConfig{
				{
					Queues: 4,
				},
			},
		}

		err := validateNodeConfig(&adqc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Invalid Globals.Numa value: abc - must be an integer or local or remote or all"))
	})

	var _ = It("Node config has invalid Cpus value", func() {
		adqc := AdqNodeConfig{
			Labels: map[string]string{
				"label": "value",
			},
			EgressMode: "skbedit",
			FilterPrio: 1,
			Globals: GlobalsConfig{
				Dev:    "eth123",
				Queues: 16,
			},
			TrafficClass: []TrafficClassConfig{
				{
					Queues: 4,
					Cpus:   "abc",
				},
			},
		}

		err := validateNodeConfig(&adqc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Invalid Cpus value: abc for TrafficClass: 0 - must be an integer list or auto"))
	})

	var _ = It("Node config has invalid Numa value", func() {
		adqc := AdqNodeConfig{
			Labels: map[string]string{
				"label": "value",
			},
			EgressMode: "skbedit",
			FilterPrio: 1,
			Globals: GlobalsConfig{
				Dev:    "eth123",
				Queues: 16,
			},
			TrafficClass: []TrafficClassConfig{
				{
					Queues: 4,
					Numa:   "abc",
				},
			},
		}

		err := validateNodeConfig(&adqc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Invalid Numa value: abc for TrafficClass: 0 - must be an integer or local or remote or all"))
	})

})
