#!/bin/sh

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Intel Corporation

# Always exit on errors.
set -e

# Trap sigterm
exitonsigterm() {
  echo "Trapped sigterm, exiting."
  exit 0
}
trap exitonsigterm TERM

# Make a adq-cni.d directory (for our kubeconfig)

CNI_CONF_DIR="/host/etc/cni/net.d"
ADQ_TEMP_KUBECONFIG="/configs-tmp/adq.kubeconfig"

mkdir -p $CNI_CONF_DIR/adq-cni.d
ADQ_KUBECONFIG=$CNI_CONF_DIR/adq-cni.d/adq.kubeconfig
ADQ_HOSTNAME=$CNI_CONF_DIR/adq-cni.d/hostname

touch $ADQ_HOSTNAME
chmod 644 $ADQ_HOSTNAME
printf %s > $ADQ_HOSTNAME "$NODE_NAME"

# ------------------------------- Generate a "kube-config"
# Inspired by: https://tinyurl.com/y7r2knme
SERVICE_ACCOUNT_PATH=/var/run/secrets/kubernetes.io/serviceaccount
KUBE_CA_FILE=${KUBE_CA_FILE:-$SERVICE_ACCOUNT_PATH/ca.crt}
SERVICEACCOUNT_TOKEN=$(cat $SERVICE_ACCOUNT_PATH/token)
SKIP_TLS_VERIFY=${SKIP_TLS_VERIFY:-false}


# Check if we're running as a k8s pod.
if [ -f "$SERVICE_ACCOUNT_PATH/token" ]; then
  # We're running as a k8d pod - expect some variables.
  if [ -z "${KUBERNETES_SERVICE_HOST}" ]; then
    error "KUBERNETES_SERVICE_HOST not set"; exit 1;
  fi
  if [ -z "${KUBERNETES_SERVICE_PORT}" ]; then
    error "KUBERNETES_SERVICE_PORT not set"; exit 1;
  fi

  if [ "$SKIP_TLS_VERIFY" = "true" ]; then
    TLS_CFG="insecure-skip-tls-verify: true"
  elif [ -f "$KUBE_CA_FILE" ]; then
    TLS_CFG="certificate-authority-data: $(< "$KUBE_CA_FILE"  base64 | tr -d '\n')"
  fi

  # Write a kubeconfig file for the CNI plugin.  Do this
  # to skip TLS verification for now.  We should eventually support
  # writing more complete kubeconfig files. This is only used
  # if the provided CNI network config references it.
  touch $ADQ_TEMP_KUBECONFIG
  chmod "${KUBECONFIG_MODE:-600}" $ADQ_TEMP_KUBECONFIG
  # Write the kubeconfig to a temp file first.
  cat > $ADQ_TEMP_KUBECONFIG <<EOF
# Kubeconfig file for ADQ CNI plugin.
apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    server: ${KUBERNETES_SERVICE_PROTOCOL:-https}://[${KUBERNETES_SERVICE_HOST}]:${KUBERNETES_SERVICE_PORT}
    $TLS_CFG
users:
- name: adq
  user:
    token: "${SERVICEACCOUNT_TOKEN}"
contexts:
- name: adq-context
  context:
    cluster: local
    user: adq
current-context: adq-context
EOF

  # Atomically move the temp kubeconfig to its permanent home.
  mv -f $ADQ_TEMP_KUBECONFIG $ADQ_KUBECONFIG

else
  warn "Doesn't look like we're running in a kubernetes environment (no serviceaccount token)"
fi

# ---------------------- end Generate a "kube-config".

# ---------------------- Generate a ADQ node config from adq-cluster-config.json
CONFIG_FILENAME=/etc/adq/adq-cluster-config.json

if [[ ! -f "$CONFIG_FILENAME" ]]; then
    echo "ADQ cluster configuration file $CONFIG_FILENAME does not exist"
    exit 1
fi

./adq-node-config
