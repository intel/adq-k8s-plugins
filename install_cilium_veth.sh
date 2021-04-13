#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Intel Corporation

export MASTER_NODE_IP="192.168.111.8"
export IFACE_NAME="ens801f0"

kubectl apply -f ./deploy/k8s/cilium-cm.yaml

helm uninstall -n kube-system cilium
helm install cilium cilium/cilium \
    --version v1.12.0 \
    --namespace kube-system \
    --set kubeProxyReplacement=strict \
    --set k8sServiceHost=$MASTER_NODE_IP \
    --set k8sServicePort=6443 \
    --set devices=$IFACE_NAME \
    --set l7Proxy=false \
    --set sockops.enabled=true \
    --set tunnel=disabled \
    --set ipv4NativeRoutingCIDR=10.244.0.0/16 \
    --set enableipv4masquerade=true \
    --set autoDirectNodeRoutes=true \
    --set endpointRoutes.enabled=true \
    --set bpf.masquerade=true \
    --set ipv4.enabled=true \
    --set disable-envoy-version-check=true \
    --set ipam.mode=kubernetes \
    --set cni.customConf=true \
    --set cni.configMap=cni-configuration \
    --set prometheus.enabled=true \
    --set operator.prometheus.enabled=true \
    --set hubble.enabled=true \
    --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}" \
    --set extraArgs='{--bpf-filter-priority=99}'
