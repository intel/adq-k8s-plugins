// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	//adqtc "github.com/intel/adq-device-plugin/pkg/adqtc"
	"github.com/intel/adq-device-plugin/pkg/netlinktc"
	"github.com/intel/adq-device-plugin/pkg/nodeconfigtypes"
	"github.com/intel/intel-device-plugins-for-kubernetes/pkg/deviceplugin"
	"github.com/intel/intel-device-plugins-for-kubernetes/pkg/topology"
	log "github.com/sirupsen/logrus"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	deviceTypeExclusiveQ = "adq"
	deviceTypeSharedQ    = "adq-shared"
	namespace            = "net.intel.com"
	annotationName       = deviceTypeExclusiveQ + "." + namespace
)

var (
	adqtcInit             = netlinktc.Init
	getTopologyInfo       = GetTopologyInfo
	newTopologyHints      = topology.NewTopologyHints
	defaultNodeConfigPath = "/etc/cni/net.d/adq-cni.d/node-config"
)

type devicePlugin struct {
	master          string
	numTC           int
	sharedTC        int
	startQueue      int
	stopQueue       int
	reconcilePeriod time.Duration
	mode            string
}

func parseFlags(name string, args []string) (dp *devicePlugin, out string, err error) {
	logger := log.WithField("func", "parseFlags")
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	var buf bytes.Buffer
	var master string
	var mode string
	var reconcilePeriod time.Duration

	flags.SetOutput(&buf)

	// 30 sec by default
	defaultReconcile, err := time.ParseDuration("30s")
	if err != nil {
		logger.WithError(err).Error("Failed to parse default value for reconcile-period parameter")
		return nil, buf.String(), err
	}

	flags.DurationVar(&reconcilePeriod, "reconcile-period", defaultReconcile, "reconcile period for device scan")
	flags.StringVar(&mode, "mode", "mixed", "adq, adq-single, mixed")

	err = flags.Parse(args)
	if err != nil {
		return nil, buf.String(), err
	}

	nodeConfig, err := os.ReadFile(defaultNodeConfigPath)
	if err != nil {
		logger.WithError(err).Errorf("Unable to read node config from %v", defaultNodeConfigPath)
	}

	var nc nodeconfigtypes.AdqNodeConfig
	err = json.Unmarshal(nodeConfig, &nc)
	if err != nil {
		return nil, "", fmt.Errorf("Error when unmarshalling node-config: %v", err)
	}

	master = nc.Globals.Dev

	// Validate
	if reconcilePeriod <= 0 {
		logger.Error("Reconcile period must be greater than 0")
		return nil, buf.String(), errors.New("reconcile period must be greater than 0")
	}
	dp, err = newDevicePlugin(master, mode, reconcilePeriod)
	return dp, buf.String(), err
}

// GetTopologyInfo returns topology information for the list of device nodes.
// copied from https://github.com/intel/intel-device-plugins-for-kubernetes/blob/0288f24b0a19f755f4e07c728e7f5f31dd2364fd/pkg/topology/topology.go#L256-L295
// GetTopologyInfo from topology.go will be used if https://github.com/intel/intel-device-plugins-for-kubernetes/pull/676#issuecomment-900930982 will be addressed
func GetTopologyInfo(devpath string) (*pluginapi.TopologyInfo, error) {
	var result pluginapi.TopologyInfo
	nodeIDs := map[int64]struct{}{}
	hints, err := newTopologyHints(devpath)
	if err != nil {
		return nil, err
	}
	for _, hint := range hints {
		if hint.NUMAs != "" {
			for _, nNode := range strings.Split(hint.NUMAs, ",") {
				nNodeID, err := strconv.ParseInt(strings.TrimSpace(nNode), 10, 64)
				if err != nil {
					return nil, fmt.Errorf("Unable to convert numa node %s into int64 err: %v", nNode, err)
				}
				if nNodeID < 0 {
					return nil, fmt.Errorf("numa node is negative: %d", nNodeID)
				}
				if _, ok := nodeIDs[nNodeID]; !ok {
					result.Nodes = append(result.Nodes, &pluginapi.NUMANode{ID: nNodeID})
					nodeIDs[nNodeID] = struct{}{}
				}
			}
		}
	}
	sort.Slice(result.Nodes, func(i, j int) bool { return result.Nodes[i].ID < result.Nodes[j].ID })
	return &result, nil
}

func newDevicePlugin(master, mode string, reconcilePeriod time.Duration) (*devicePlugin, error) {
	logger := log.WithField("func", "newDevicePlugin")
	numTC, sharedTC, startQ, stopQ, err := getTCValues(master, mode)
	if err != nil {
		logger.WithError(err).Error("Unable to initialize TC values")
		return nil, err
	}
	logger.Debugf("Mode %v TC info => tc: %v, shared TC %v, startQ: %v, stopQ: %v", mode, numTC, sharedTC, startQ, stopQ)
	logger.Debugf("Reconcile period value for device scan: %v", reconcilePeriod)

	return &devicePlugin{
		master:          master,
		reconcilePeriod: reconcilePeriod,
		mode:            mode,
		numTC:           numTC,
		startQueue:      startQ,
		sharedTC:        sharedTC,
		stopQueue:       stopQ,
	}, nil
}

func getNetDevPath(iface string) string {
	return "/sys/class/net/" + iface + "/device/"
}

// This is overridden in the linker script
var BuildVersion = "version unknown"

func (dp *devicePlugin) scan() (deviceplugin.DeviceTree, error) {
	logger := log.WithField("func", "scan")
	devTree := deviceplugin.NewDeviceTree()
	topology, err := getTopologyInfo(getNetDevPath(dp.master))
	if err != nil {
		logger.Errorf("Unable to get topology info for: %v err: %v", dp.master, err)
	}
	for i := 1; i < dp.numTC; i++ {
		if i == dp.sharedTC {
			continue
		}
		TC := fmt.Sprintf("%d", i)
		envs := map[string]string{}
		annotations := map[string]string{}
		nodes := []pluginapi.DeviceSpec{}
		mount := []pluginapi.Mount{}
		devTree.AddDevice(deviceTypeExclusiveQ, TC,
			deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy, nodes, mount, envs, annotations, topology))
	}

	for i := dp.startQueue; i <= dp.stopQueue; i++ {
		queue := fmt.Sprintf("%d", i)
		envs := map[string]string{}
		annotations := map[string]string{}
		nodes := []pluginapi.DeviceSpec{}
		mount := []pluginapi.Mount{}
		devTree.AddDevice(deviceTypeSharedQ, queue,
			deviceplugin.NewDeviceInfoWithTopologyHints(pluginapi.Healthy, nodes, mount, envs, annotations, topology))
	}

	return devTree, nil
}

func (dp *devicePlugin) PostAllocate(response *pluginapi.AllocateResponse) error {
	if len(dp.master) > 0 {
		for _, containerResponse := range response.GetContainerResponses() {
			containerResponse.Annotations = map[string]string{
				annotationName: dp.master,
			}
		}
	}

	return nil
}

func (dp *devicePlugin) Scan(notifier deviceplugin.Notifier) error {
	logger := log.WithField("func", "Scan")
	for {
		devTree, err := dp.scan()
		if err != nil {
			logger.Error("Error during devices' scan")
			return err
		}
		notifier.Notify(devTree)
		time.Sleep(dp.reconcilePeriod)
	}
}

func getTCValues(master, mode string) (int, int, int, int, error) {
	logger := log.WithField("func", "getTCValues")
	var (
		numTC    int = 0
		sharedTC int = -1
		startQ   int = 0
		stopQ    int = -1
	)

	object, err := adqtcInit(master, false)
	if err != nil {
		logger.Error("Failed to init adqtc")
		return numTC, sharedTC, startQ, stopQ, err
	}

	if mode != "adq-single" {
		numTC = int(object.GetNumTC())
	}

	if mode != "adq" {
		shared, err := object.GetSharedTC()
		if err != nil {
			logger.Error("Failed to get Shared TC number")
			return numTC, sharedTC, startQ, stopQ, err
		}
		sharedTC = int(shared)
		start, stop, err := object.TCGetStartStopQ(shared)
		if err != nil {
			logger.Error("Failed to get mapped queues values for Shared TC feature")
			return numTC, sharedTC, startQ, stopQ, err
		}

		if stop > 0 {
			stop = stop - 1 // not use last queue of last TC - skbedit action restriction
		}

		startQ = int(start)
		stopQ = int(stop)
	}

	return numTC, sharedTC, startQ, stopQ, nil
}

func main() {
	log.Debugf("ADQ DevicePlugin version %v", BuildVersion)
	plugin, out, err := parseFlags(os.Args[0], os.Args[1:])
	if err == flag.ErrHelp {
		log.Infoln(out)
		os.Exit(2)
	} else if err != nil {
		log.Error(out)
		os.Exit(1)
	}
	// Run new device plugin server
	log.Infof("Running ADQ device plugin for device %v", plugin.master)

	manager := deviceplugin.NewManager(namespace, plugin)
	manager.Run()
}
