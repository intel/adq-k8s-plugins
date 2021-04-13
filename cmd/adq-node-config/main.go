// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"
	"text/template"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	. "github.com/intel/adq-device-plugin/pkg/nodeconfigtypes"
)

var (
	defaultADQKubeConfigPath    = "/host/etc/cni/net.d/adq-cni.d/adq.kubeconfig"
	defaultNodeConfigPath       = "/host/etc/cni/net.d/adq-cni.d/node-config"
	defaultAdqsetupConfigPath   = "/adqsetup-config/adqsetup.conf"
	defaultADQClusterConfigPath = "/etc/adq/adq-cluster-config.json"
	getNetInterfaces            = net.Interfaces
	getClusterConfig            = getClusterConfigFromFile
)

func getNode(nodeName string) (*v1.Node, error) {
	config, err := clientcmd.BuildConfigFromFlags("", defaultADQKubeConfigPath)
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	nodes, err := client.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{
		FieldSelector: "metadata.name=" + nodeName})
	if err != nil {
		return nil, err
	}

	if len(nodes.Items) == 0 {
		return nil, fmt.Errorf("Unable to get node:%s from k8s API", nodeName)
	}

	return &nodes.Items[0], nil
}

func getIfaceName(node *v1.Node) (string, error) {
	if node == nil {
		return "", errors.New("Node is nil")
	}

	var internalIP string
	for _, adr := range node.Status.Addresses {
		if adr.Type == v1.NodeInternalIP {
			internalIP = adr.Address
		}
	}

	if internalIP == "" {
		return "", errors.New("Empty node InternalIP")
	}

	ifaceList, err := getNetInterfaces()
	if err != nil {
		return "", err
	}

	var ifaceName string
	for _, i := range ifaceList {
		addrs, err := i.Addrs()
		if err != nil {
			log.Printf("Unable to get Addrs for interface %v err:%v", i.Name, err)
			continue
		}
		for _, addr := range addrs {
			if strings.HasPrefix(addr.String(), internalIP) {
				ifaceName = i.Name
			}
		}
	}

	if ifaceName == "" {
		return "", errors.New("Master interface not found")
	}

	return ifaceName, nil
}

func getClusterConfigFromFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func getMatchingADQNodeConfig(path string, node *v1.Node) (*AdqNodeConfig, error) {
	cfg, err := getClusterConfig(path)
	if err != nil {
		return nil, err
	}

	clusterConfig := AdqClusterConfig{}
	err = json.Unmarshal(cfg, &clusterConfig)
	if err != nil {
		return nil, fmt.Errorf("Json Unmarshall error: %v", err.Error())
	}

	for _, c := range clusterConfig.NodeConfigs {
		match := true
		for k, v := range c.Labels {
			if node.Labels[k] != v {
				match = false
				break
			}
		}

		if match {
			return &c, nil
		}
	}

	return nil, nil
}

func getAdqsetupConfig(nodeConfig AdqNodeConfig) (string, error) {
	templ, err := template.New("adqsetup").Parse(
		"[globals]\n" +
			"{{if .Globals.Arpfilter}}arpfilter = on\n{{end}}" +
			"{{if .Globals.Bpstop}}bpstop = on\n{{end}}" +
			"{{if .Globals.BpstopCfg}}bpstop-cfg = on\n{{end}}" +
			"busypoll = {{ .Globals.Busypoll}}\n" +
			"busyread = {{ .Globals.Busyread}}\n" +
			"{{if .Globals.Cpus }}cpus = {{ .Globals.Cpus}}\n{{end}}" +
			"{{if .Globals.Numa }}numa = {{ .Globals.Numa}}\n{{end}}" +
			"{{if .Globals.Dev }}dev = {{ .Globals.Dev}}\n{{end}}" +
			"{{if .Globals.Optimize }}optimize = on\n{{end}}" +
			"{{if ne .Globals.Queues 0}}queues = {{ .Globals.Queues}}\n{{end}}" +
			"{{if ne .Globals.Txring 0}}txring = {{ .Globals.Txring}}\n{{end}}" +
			"{{if .Globals.Txadapt }}txadapt = on\n{{else}}txadapt = off\n{{end}}" +
			"{{if ne .Globals.Txusecs 0}}txusecs = {{ .Globals.Txusecs}}\n{{end}}" +
			"{{if ne .Globals.Rxring 0}}rxring = {{ .Globals.Rxring}}\n{{end}}" +
			"{{if .Globals.Rxadapt }}rxadapt = on\n{{else}}rxadapt = off\n{{end}}" +
			"{{if ne .Globals.Rxusecs 0}}rxusecs = {{ .Globals.Rxusecs}}\n{{end}}\n" +
			"{{range $index, $elem := .TrafficClass}}" +
			"[adqTC{{$index}}]\n" +
			"mode = {{.Mode}}\n" +
			"queues = {{.Queues}}\n" +
			"{{if ne .Pollers 0}}pollers = {{ .Pollers}}\n{{end}}" +
			"{{if ne .PollerTimeout 0}}poller-timeout = {{ .PollerTimeout}}\n{{end}}" +
			"{{if .Cpus}}cpus = {{ .Cpus}}\n{{end}}" +
			"{{if .Numa}}numa = {{ .Numa}}\n{{end}}" +
			"{{if .Numa}}numa = {{ .Numa}}\n{{end}}" +
			"\n{{end}}")

	if err != nil {
		return "", fmt.Errorf("Unable to parse adqsetup config template err:%s", err.Error())
	}

	result := new(bytes.Buffer)
	err = templ.Execute(result, nodeConfig)

	return result.String(), err
}

func validateNodeConfig(nodeConfig *AdqNodeConfig) error {
	if nodeConfig == nil {
		return fmt.Errorf("Node config is empty")
	}

	if len(nodeConfig.Labels) == 0 {
		return fmt.Errorf("Node config has no labels specified")
	}

	if nodeConfig.Globals.Rxusecs != 0 && nodeConfig.Globals.Rxadapt {
		return fmt.Errorf("If Rxusecs is set Rxadapt must be turned off")
	}

	if nodeConfig.Globals.Txusecs != 0 && nodeConfig.Globals.Txadapt {
		return fmt.Errorf("If Txusecs is set Txadapt must be turned off")
	}

	var cpusRegex = regexp.MustCompile(`^(\d+\,*)+$|auto`)
	var numaRegex = regexp.MustCompile(`^\d+$|local|remote|all`)

	if nodeConfig.Globals.Cpus != "" && cpusRegex.FindString(nodeConfig.Globals.Cpus) == "" {
		return fmt.Errorf("Invalid Globals.Cpus value: %s - must be an integer list or auto", nodeConfig.Globals.Cpus)
	}

	if nodeConfig.Globals.Numa != "" && numaRegex.FindString(nodeConfig.Globals.Numa) == "" {
		return fmt.Errorf("Invalid Globals.Numa value: %s - must be an integer or local or remote or all", nodeConfig.Globals.Numa)
	}

	for i := range nodeConfig.TrafficClass {
		if nodeConfig.TrafficClass[i].Cpus != "" && cpusRegex.FindString(nodeConfig.TrafficClass[i].Cpus) == "" {
			return fmt.Errorf("Invalid Cpus value: %s for TrafficClass: %d - must be an integer list or auto", nodeConfig.TrafficClass[i].Cpus, i)
		}

		if nodeConfig.TrafficClass[i].Numa != "" && numaRegex.FindString(nodeConfig.TrafficClass[i].Numa) == "" {
			return fmt.Errorf("Invalid Numa value: %s for TrafficClass: %d - must be an integer or local or remote or all", nodeConfig.TrafficClass[i].Numa, i)
		}
	}

	// overwrite modes to make only the last traffic class shared
	for i := range nodeConfig.TrafficClass {
		if i < len(nodeConfig.TrafficClass)-1 {
			nodeConfig.TrafficClass[i].Mode = "exclusive"
		} else {
			nodeConfig.TrafficClass[i].Mode = "shared"
		}
	}

	if nodeConfig.EgressMode != "netprio" && nodeConfig.EgressMode != "skbedit" {
		return fmt.Errorf("Invalid egress mode: %s - supported: netprio or skbedit", nodeConfig.EgressMode)
	}

	return nil
}

func getNodeConfig(node *v1.Node, ifaceName, path string) (string, string, error) {
	nodeConfig, err := getMatchingADQNodeConfig(path, node)
	if err != nil {
		return "", "", err
	}

	if nodeConfig == nil {
		return "", "", fmt.Errorf("Node config is empty")
	}

	// Use discovered master interface name if not defined in Globals
	if nodeConfig.Globals.Dev == "" {
		nodeConfig.Globals.Dev = ifaceName
	}

	err = validateNodeConfig(nodeConfig)
	if err != nil {
		return "", "", fmt.Errorf("Node config validation error: %v", err)
	}

	adqsetupConfig, err := getAdqsetupConfig(*nodeConfig)
	if err != nil {
		return "", "", err
	}

	nodeConfigJson, err := json.MarshalIndent(nodeConfig, "", "    ")
	if err != nil {
		return "", "", err
	}

	return adqsetupConfig, string(nodeConfigJson), nil
}

// This is overridden in the linker script
var BuildVersion = "version unknown"

func main() {
	log.Debugf("ADQ Node Config version %v", BuildVersion)
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Error("Unable to get K8s node name from ENV var NODE_NAME")
		os.Exit(1)
	}

	node, err := getNode(nodeName)
	if err != nil {
		log.Errorf("Unable to get node: %v", err)
		os.Exit(1)
	}

	ifaceName, err := getIfaceName(node)
	if err != nil {
		log.Errorf("Unable to get interface name: %v", err)
		os.Exit(1)
	}

	adqsetupConfig, nodeConfig, err := getNodeConfig(node, ifaceName, defaultADQClusterConfigPath)
	if err != nil {
		log.Errorf("Unable to get node config: %v", err)
		os.Exit(1)
	}

	// contains config file for adqsetup tool
	err = os.WriteFile(defaultAdqsetupConfigPath, []byte(adqsetupConfig), 0644)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	// contains Master interface name and egress mode
	err = os.WriteFile(defaultNodeConfigPath, []byte(nodeConfig), 0644)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
}
