```text
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2022 Intel Corporation
```

<!-- omit in toc -->
# Release Notes

This document provides high-level system features, issues, and limitations information for Intel® ADQ CNI.

- [Release History](#release-history)
- [Features for Release](#features-for-release)
- [Changes to Existing Features](#changes-to-existing-features)
- [Fixed Issues](#fixed-issues)
- [Known Issues and Limitations](#known-issues-and-limitations)
- [Release Content](#release-content)
- [Supported Hardware](#supported-hardware)
- [Supported Software](#supported-software)

## Release History

| Version   | Release Date     |
|-----------|------------------|
| 22.06-1   | 1 September 2022 |
| 22.06     | 26 August 2022   |
| 22.06-rc4 | 21 July 2022     |
| 22.06-rc3 | 21 June 2022     |
| 22.06-rc2 | 21 June 2022     |
| 22.06-rc1 | 11 May 2022      |

## Features for Release

***22.06***

- Master interface can now be configured in adq-cluster-config.yaml (.Globals.Dev) instead of the cni-configuration

- Experimental support for VXLAN Cilium

***22.06-rc4***

- ADQ filter priority can be configured in adq-cluster-config.yaml (FilterPrio in adq-cluster-config.yaml).

- Egress traffic is now filtered using skbedit instead of netprio.

  Netprio still exists as an option (EGRESS_MODE in adq-cluster-config.yaml).

***22.06-rc1***

- Intel® ADQ CNI
  - ADQ CNI Daemonset handles host setup and CNI Plugin installation
  - ADQ CNI Daemonset provides device plugin that enables `net.intel.com/adq` resource
  - ADQ CNI Daemonset handles pod egress traffic steering through `net_prio.ifpriomap` configuration
  - CNI Plugin handles the ingress flower filter configuration
- Optional ADQ Prometheus exporter
  - Exposes queue statistics from CVL interface
  - Example grafana dashboard included

## Changes to Existing Features

***22.06-1***

- adqsetup version bumped to 2.0

***22.06***

- README and documentation improvements

- adqsetup version bumped and frozen to the latest 2.0rc3

- Fix for adq-netprio behavior while handling pods containing init containers

- Security improvements in adq-cni-dp daemonset spec

- Go dependency update

- Alpine is now used as a base image for adqsetup tool

***22.06-rc4***

- adqsetup tool is now used to configure nodes.

- Empty ADQ pod annotations now accelerate all ports in pod.

## Fixed Issues

***22.06-rc4***

- Invalid ADQ pod annotations now always fail.

***22.06-rc1***

- n/a - this is the first release.

## Known Issues and Limitations

- The installation of the out of tree [ICE driver](https://www.intel.com/content/www/us/en/download/19630/intel-network-adapter-driver-for-e810-series-devices-under-linux.html) is necessary for correct functionality of the ADQ CNI.

## Release Content

- Intel® ADQ CNI source code
- ADQ CNI daemonset .yaml
- `cni-configuration` configmap that enables chaining ADQ CNI to Cilium CNI
- Example ADQ cluster configuration
- Optional ADQ prometheus exporter for interface statistics and Grafana dashboard
- Documentation

## Supported Hardware

- Intel® Ethernet Controller E810-C
- TBD

## Supported Software

Relases were tested using the following software:

***22.06-1***

- Kubernetes v1.24.3
- OS: CentOS Stream 8 (centos-stream-release-8.6-1.el8.noarch)
- Kernel: Linux 5.18.15-1.el8.elrepo.x86_64
- ICE Driver: 1.9.11
- Container Runtime: cri-o 1.21.3, containerd 1.6.7
- CNI: Cilium 1.12
- adqsetup: 2.0

***22.06***

- Kubernetes v1.24.3
- OS: CentOS Stream 8 (centos-stream-release-8.6-1.el8.noarch)
- Kernel: Linux 5.18.15-1.el8.elrepo.x86_64
- ICE Driver: 1.9.11
- Container Runtime: cri-o 1.21.3, containerd 1.6.7
- CNI: Cilium 1.12
- adqsetup: 2.0rc3
  
***22.06-rc4***

- Kubernetes v1.24.3
- OS: CentOS Stream 8 (centos-stream-release-8.6-1.el8.noarch)
- Kernel: Linux 5.18.15-1.el8.elrepo.x86_64
- ICE Driver: 1.9.11
- Container Runtime: cri-o 1.21.3
- CNI: Cilium 1.12

***22.06-rc3***

- Kubernetes v1.21.8
- OS: CentOS Stream 8 (centos-stream-release-8.6-1.el8.noarch)
- Kernel: Linux 5.13.13-1.el8.elrepo.x86_64
- ICE Driver: 1.8.8
- Container Runtime: cri-o 1.21.0
- CNI: Cilium 1.10.8

***22.06-rc2***

- Kubernetes v1.21.8
- OS: CentOS Stream 8 (centos-stream-release-8.6-1.el8.noarch)
- Kernel: Linux 5.13.13-1.el8.elrepo.x86_64
- ICE Driver: 1.7.16
- Container Runtime: cri-o 1.21.0
- CNI: Cilium 1.10.8

***22.06-rc1***

- Kubernetes v1.21.8
- OS: CentOS Stream 8 (centos-stream-release-8.6-1.el8.noarch)
- Kernel: Linux 5.13.13-1.el8.elrepo.x86_64
- ICE Driver: 1.7.16
- Container Runtime: cri-o  1.21.0
- CNI: Cilium 1.10.8
