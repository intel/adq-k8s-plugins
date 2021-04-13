// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation

package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/intel/adq-device-plugin/pkg/kubeletclient"
	"github.com/intel/adq-device-plugin/pkg/netlinktc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"

	"github.com/safchain/ethtool"

	"golang.org/x/time/rate"
)

var (
	addr = flag.String("address", ":33000", "Address on which metrics are exposed")

	ethtoolSupportedStatNames = []string{
		"pkt_busy_poll",
		"pkt_not_busy_poll",
		"in_bp",
		"in_intr",
		"intr_to_bp",
		"bp_to_bp",
		"bp_to_intr",
		"intr_to_intr",
		"queue_set",
		"tcp_fin_recv",
		"tcp_rst_recv",
		"tcp_syn_recv",
		"atr_setup",
	}

	sanitizeNameRegex = regexp.MustCompile(`[^a-zA-Z0-9_]`)
	queueNumberRegex  = regexp.MustCompile(`^(tx_|rx_)(\d+)\.(\S+)`)
)

const (
	envNodeName         = "NODE_NAME"
	supportedDriverName = "ice"
	unallocatedStr      = "unallocated"
)

type ethtoolInterface interface {
	DriverName(intf string) (string, error)
	Stats(intf string) (map[string]uint64, error)
}

type adqCollector struct {
	matchingStatsRegex *regexp.Regexp
	entries            map[string]*prometheus.Desc
	ethHandle          ethtoolInterface
}

var (
	getNetInterfaces = net.Interfaces
	getEthtool       = func() (ethtoolInterface, error) { return ethtool.NewEthtool() }
	adqtcInit        = netlinktc.Init
	getKubeletClient = kubeletclient.GetKubeletClient
)

type interfaceStats map[string]uint64

type prometheusHandler struct {
	handler http.Handler
}

var limiter = rate.NewLimiter(1, 3)

func (ph *prometheusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Only GET requests are allowed!", http.StatusMethodNotAllowed)
		return
	}
	if !limiter.Allow() {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}
	ph.handler.ServeHTTP(w, r)
}

// getMatchingStats() retrieves statistics (equivalent to ethtool -S) from all the interfaces
// (that use the ice driver) and names match the ones from ethtoolSupportedStatNames variable
func (adqc *adqCollector) getMatchingStats() (map[string]interfaceStats, error) {
	logger := log.WithField("func", "getMatchingStats")
	if adqc.ethHandle == nil {
		return nil, fmt.Errorf("ethtool handler not initialized")
	}

	ifs, err := getNetInterfaces()
	if err != nil {
		return nil, fmt.Errorf("Unable to get network interfaces err:%v", err)
	}

	result := map[string]interfaceStats{}
	for _, i := range ifs {
		driverName, err := adqc.ethHandle.DriverName(i.Name)
		if err != nil {
			logger.Debugf("Unable to get driver info for interface:%v skipping", i.Name)
			continue
		}
		if driverName != supportedDriverName {
			continue
		}

		stats, err := adqc.ethHandle.Stats(i.Name)
		if err != nil {
			logger.Debugf("Unable to get stats for interface %v err: %v - skipping", i.Name, err)
			continue
		}

		matchingStats := map[string]uint64{}
		for key, val := range stats {
			if adqc.matchingStatsRegex.MatchString(key) {
				matchingStats[key] = val
			}
		}
		result[i.Name] = matchingStats
	}
	return result, nil
}

// transformName() removes queue number from ethtool statistics and replaces all unsupported metric name characters
// with "_" eg: tx_160.pkt_busy_poll is transformed into tx_pkt_busy_poll
func transformName(name string) string {
	result := ""
	matches := queueNumberRegex.FindStringSubmatch(name)
	if len(matches) == 4 {
		result = sanitizeNameRegex.ReplaceAllString(matches[1]+matches[3], "_")
	}
	return result
}

// NewAdqCollector() returns new adq collector with initialized Description map (prometheus.Desc)
// for all matching stats from network interfaces
func NewAdqCollector() (*adqCollector, error) {
	eth, err := getEthtool()
	if err != nil {
		return nil, fmt.Errorf("Unable to create ethtool handler:%v", err)
	}

	r, err := regexp.Compile(strings.Join(ethtoolSupportedStatNames, "|"))
	if err != nil {
		return nil, fmt.Errorf("Unable to compile regex for matching stats:%v", err)
	}

	adqc := &adqCollector{
		ethHandle:          eth,
		matchingStatsRegex: r,
	}
	ms, err := adqc.getMatchingStats()
	if err != nil {
		return nil, fmt.Errorf("Unable to retrieve matching stats:%v", err)
	}

	entries := map[string]*prometheus.Desc{}
	for _, v := range ms {
		for key := range v {
			name := transformName(key)
			if _, exists := entries[name]; !exists && name != "" {
				entries[name] = prometheus.NewDesc(
					prometheus.BuildFQName("", "adq", name),
					name,
					[]string{"adq_node_name", "adq_nic", "adq_pod_name",
						"adq_pod_namespace", "adq_container_name", "adq_pod_adq_resource",
						"adq_queue_number", "adq_tc_number"},
					nil,
				)
			}
		}
	}

	adqc.entries = entries
	return adqc, nil
}

// isQueueInTC() checks if provided queue number is in queue range of provided TC
func isQueueInTC(object netlinktc.NetlinkTc, qNum uint16, tcNum uint8) (bool, error) {
	start, stop, err := object.TCGetStartStopQ(tcNum)
	if err != nil {
		return false, err
	}

	if qNum >= start && qNum <= stop {
		return true, nil
	} else {
		return false, nil
	}
}

func init() {
	log.SetLevel(log.DebugLevel)
}

func main() {
	logger := log.WithField("func", "main")
	flag.Parse()

	collector, err := NewAdqCollector()
	if err != nil {
		logger.Errorf("Error when creating ADQ collector: %v", err)
		os.Exit(1)
	}
	prometheus.MustRegister(collector)

	http.Handle("/metrics", &prometheusHandler{handler: promhttp.Handler()})
	err = http.ListenAndServe(*addr, nil)
	if err != nil {
		logger.Errorf("adq-exporter http server returned:%v", err)
		os.Exit(1)
	}
}

type adqLabels struct {
	podName          string
	podNamespace     string
	containerName    string
	podAdqResource   string
	queueNumber      string
	tcNumber         string
	networkInterface string
	nodeName         string
}

// getLabels() does the lookup through pod resource and returns the pod information (name, namespace, etc) if
// maching one to provided queue is found
func getLabels(podResource *podresourcesapi.PodResources, object netlinktc.NetlinkTc, queueNumber uint16) adqLabels {
	logger := log.WithField("func", "getLabels")
	labels := adqLabels{}
	for _, c := range podResource.Containers {
		for _, d := range c.Devices {
			tcNum, err := strconv.ParseUint(d.DeviceIds[0], 10, 16)
			if err != nil {
				logger.Errorf("Unable to convert TC number:%v", err)
				continue
			}

			if d.ResourceName == kubeletclient.AdqResourceName {
				match, err := isQueueInTC(object, queueNumber, uint8(tcNum))
				if err != nil {
					logger.Errorf("Unable to check if queue is in TC:%v", err)
					continue
				}

				// passed queueNumber corresponds to the TC assigned to pod
				if match {
					labels.podName = podResource.Name
					labels.podNamespace = podResource.Namespace
					labels.containerName = c.Name
					labels.podAdqResource = kubeletclient.AdqResourceName
					labels.tcNumber = strconv.Itoa(int(tcNum))
				}
			}

			if d.ResourceName == kubeletclient.AdqSharedResourceName && queueNumber == uint16(tcNum) {
				sharedTCNumber, err := object.GetSharedTC()
				if err != nil {
					logger.Errorf("Unable to get shared TC number%v", err)
					continue
				}
				match, err := isQueueInTC(object, queueNumber, sharedTCNumber)
				if err != nil {
					logger.Errorf("Unable to check if queue is in TC:%v", err)
					continue
				}

				// passed queueNumber corresponds to the TC assigned to pod (shared)
				if match {
					labels.podName = podResource.Name
					labels.podNamespace = podResource.Namespace
					labels.containerName = c.Name
					labels.podAdqResource = kubeletclient.AdqSharedResourceName
					labels.tcNumber = strconv.Itoa(int(sharedTCNumber))
				}
			}
		}
	}
	return labels
}

// Describe() sends descriptions to the prometheus channel
func (adqc *adqCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, e := range adqc.entries {
		ch <- e
	}
}

// Collect() retrieves statistics from network interfaces, retrieves pod resource information, creates prometheus
// metrics and sends them to prometheus channel
func (adqc *adqCollector) Collect(ch chan<- prometheus.Metric) {
	logger := log.WithField("func", "Collect")
	ifStats, err := adqc.getMatchingStats()
	if err != nil {
		logger.Errorf("Unable to retrieve matching stats:%v", err)
		return
	}

	for interfaceName, interfaceStats := range ifStats {
		object, err := adqtcInit(interfaceName, false)
		if err != nil {
			logger.Debugf("Cannot initialize tc module for interface:%v...skipping err %v",
				interfaceName, err)
			continue
		}

		kc, err := getKubeletClient(false, "", "", "")
		if err != nil {
			logger.Errorf("Unable to get kubeletclient:%v", err)
			return
		}

		for key, value := range interfaceStats {
			matches := queueNumberRegex.FindStringSubmatch(key)
			if len(matches) == 4 {
				queueNumber := matches[2]
				labels := adqLabels{}
				for _, p := range kc.GetPodResources() {
					qNum, err := strconv.ParseUint(queueNumber, 10, 16)
					if err != nil {
						logger.Errorf("Unable to convert queue number:%v", err)
						continue
					}

					labels = getLabels(p, object, uint16(qNum))
					if labels.podName != "" {
						break // pod found
					}
				}

				if labels.podName == "" {
					labels.podName = unallocatedStr
					labels.podNamespace = unallocatedStr
					labels.tcNumber = unallocatedStr
				}

				labels.queueNumber = queueNumber
				labels.networkInterface = interfaceName
				labels.nodeName = os.Getenv(envNodeName)

				name := transformName(key)
				if _, exists := adqc.entries[name]; exists {
					ch <- prometheus.MustNewConstMetric(adqc.entries[name], prometheus.GaugeValue, float64(value),
						labels.nodeName,
						labels.networkInterface,
						labels.podName,
						labels.podNamespace,
						labels.containerName,
						labels.podAdqResource,
						labels.queueNumber,
						labels.tcNumber,
					)
				}
			}
		}
	}
}
