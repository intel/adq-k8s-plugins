// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation

package nodeconfigtypes

type AdqClusterConfig struct {
	NodeConfigs []AdqNodeConfig
}

type AdqNodeConfig struct {
	Labels       map[string]string
	EgressMode   string
	FilterPrio   uint16
	Globals      GlobalsConfig
	TrafficClass []TrafficClassConfig
}

type GlobalsConfig struct {
	Arpfilter bool
	Bpstop    bool
	BpstopCfg bool
	Busypoll  uint32
	Busyread  uint32
	Cpus      string
	Numa      string
	Dev       string
	Optimize  bool
	Queues    uint32
	Txring    uint32
	Txadapt   bool
	Txusecs   uint32
	Rxring    uint32
	Rxadapt   bool
	Rxusecs   uint32
}

type TrafficClassConfig struct {
	Mode          string
	Queues        uint32
	Pollers       uint32
	PollerTimeout uint32
	Cpus          string
	Numa          string
}
