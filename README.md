# Kubernetes ADQ integration

- [Kubernetes ADQ integration](#kubernetes-adq-integration)
  - [Deployment on existing Kubernetes cluster](#deployment-on-existing-kubernetes-cluster)
    - [Requirements](#requirements)
  - [Prometheus/Grafana](#prometheusgrafana)
  - [Testing environment](#testing-environment)
  - [Proxy settings](#proxy-settings)
  - [Cluster configuration](#cluster-configuration)
    - [TC/Queue Configuration](#tcqueue-configuration)
    - [Independent poller configuration](#independent-poller-configuration)

## Deployment on existing Kubernetes cluster

### Requirements

* Working Kubernetes cluster that does not use kube proxy (--skip-phases=addon/kube-proxy flag set at cluster init)
* ADQ enabled 810 Intel Ethernet Network Adapter, with firmware 4.00 or newer that is used for the Kubernetes cluster network
* [Intel ice driver](https://sourceforge.net/projects/e1000/files/ice%20stable/) that has been built with ADQ flag set

   ```sh
   make -j$(nproc) CFLAGS_EXTRA='-DADQ_PERF_COUNTERS' install
   ```

* HELM installed
* Firewall rules set following [cilium documentation](https://docs.cilium.io/en/latest/operations/system_requirements/#firewall-rules) or disable firewall altogether

1. Download code

   ```sh
   git clone https://github.com/intel/adq-k8s-plugins.git
   ```

2. Install cilium

   * To use project's default CNI configuration fill variables at the top of the script with appropriate values and execute it:

     ```sh
     ./install_cilium_veth.sh
     ```

   * Or proceed with custom CNI install:

     Apply cilium configMap.

     ```sh
     kubectl apply -f deploy/k8s/cilium-cm.yaml
     ```

     During your cilium install make sure to include following options in order to use configMap you applied earlier. Otherwise adq-cni will not be used and device plugin will not work.

     ```sh
     --set cni.customConf=true
     --set cni.configMap=cni-configuration
     ```

3. Edit [deploy/k8s/adq-cluster-config.yaml](deploy/k8s/adq-cluster-config.yaml) if you would like to change pollers or queues [configuration](#cluster-configuration) across the cluster.

   Make sure to update line #20 in [adq-cluster-config.yaml](deploy/k8s/adq-cluster-config.yaml) with your control node network interface name, or delete it and the CNI will pick up interface used for the Kubernetes cluster automatically.

   Apply the configuration.

   ```sh
   kubectl apply -f deploy/k8s/adq-cluster-config.yaml
   ```

4. Build the images and push to registry of choice

   ```sh
   make docker-build IMAGE_REGISTRY=<YOUR_REGISTRY>:5000/ IMAGE_VERSION=<TAG>
   make docker-push IMAGE_REGISTRY=<YOUR_REGISTRY>:5000/ IMAGE_VERSION=<TAG>
   ```

5. Deploy ADQ CNI/DP

   Edit lines #23, #32, #50, #63 and #82 in deploy/k8s/adq-cni-dp-ds.yaml to `<YOUR_REGISTRY>:5000/adq-cni-dp:<TAG>` and `<YOUR_REGISTRY>:5000/adqsetup:<TAG>`

   ```sh
   kubectl apply -f deploy/k8s/adq-cni-dp-ds.yaml
   ```

## Prometheus/Grafana

The adq-prometheus-exporter is optional, and is included in the adq-monitoring.yml. Covered in Prometheus/Grafana section.

1. Ensure that GOPATH is set and GOPATH/bin is in PATH
2. Install

   ```sh
   make deploy-prometheus
   make enable-adq-telemetry
   ```

3. Forward ports using ssh

   ```sh
   ssh -NL 9090:<PROMETHEUS-SERVICE-IP>:9090 -NL 3000:<GRAFANA-POD-IP>:3000 user@<IP-MACHINE-WITH-CONTROL-NODE>
   ```

4. Set proxy in your web browser if needed
5. Access via browser from computer

   ```sh
   http://localhost:3000   # for Grafana
   http://localhost:9090   # for Prometheus
   ```

## Testing environment

Minimum kernel version supported is 5.6 which must include modules sch_mqprio, act_mirred, cls_flower which may not be downloaded by defualt.

| Name | Version |
| :----: |  :----: |
| OS |  Centos Stream 8 |
| Kernel | 5.18.7-1 |
| Docker-ce | 20.10.17 |
| Docker-ce-cli | 20.10.17 |
| containerd.io | 1.6.6 |
| Ice Driver | ice-1.9.11 |
| CRI-O | 1.22.5 |
| kubelet | 1.25.11 |
| kubeadm | 1.25.11 |
| kubectl | 1.25.11 |
| Cilium | 1.12.0 |

## Proxy settings

Proxy configuration is different for each installation environment, so care should be taken to understand the required proxy settings for a particular environment as misconfiguration may greatly disrupt this installation. The settings below need to be configured if the control node and worker node are behind a proxy.

```sh
hostIp=$(ip -o route get to 8.8.8.8 | sed -n 's/.*src \([0-9.]\+\).*/\1/p')

export no_proxy="${no_proxy},${hostIp},10.96.0.0/12,10.244.0.0/16,192.168.0.1,192.168.0.2"

# 10.96.0.0/12 is the CIDR of the kubernetes service

# 10.244.0.0/16 is the CIDR of the pod network

# 192.168.0.1 is the IP address of the remote 810 Intel Ethernet Newtwork Adapter port

# 192.168.0.2 is the IP address of the local 810 Intel Ethernet Newtwork Adapter port
```

For setup behind a proxy you may also need to set proxies for the container runtime. For example for containerd edit /etc/systemd/system/containerd.service.d/http-proxy.conf

```sh
[Service]

Environment="HTTP_PROXY=http://example-proxy.com"

Environment="HTTPS_PROXY=http://example-proxy.com"

Environment="NO_PROXY=localhost,127.0.0.1,10.96.0.0/12,10.244.0.0/16,192.168.0.1,192.168.0.2"
```

## Cluster configuration

In order to configure ADQ functionality you can edit [deploy/k8s/adq-cluster-config.yaml](deploy/k8s/adq-cluster-config.yaml). The list of parameters that can be altered are:
| Globals   |Meaning |
| :----     |  :---- |
| Arpfilter | Enable selective ARP activity |
| Bpstop    | Channel-packet-clean-bp-stop feature  |
| BpstopCfg | Channel-packet-clean-bp-stop-cfg feature |
| Cpus      | CPUs to use for handling 'default' traffic, default 'auto' |
| Numa      | Numa node to use for 'default' traffic, default 'all' |
| Dev       | Network interface device to configure |
| Optimize  |  Channel-inspect-optimize feature |
| Queues    | Number of queues in 'default' traffic class, default 2 |
| Txring    | Transmit ring buffer size |
| Txadapt   | Adaptive transmit interrupt coalescing |
| Txusecs   | Usecs for transmit interrupt coalescing |
| Rxring    | Receive ring buffer size |
| Rxadapt   | Adaptive receive interrupt coalescing |
| Rxusecs   | Usecs for receive interrupt coalescing |

| TrafficClass |Meaning |
| :----        |  :---- |
| Mode         | Mode for traffic class
| Queues       | Number of queues in traffic class
| Pollers      | Number of independent pollers, default 0
| PollerTimeout| Independent poller timeout value, default 10000
| Cpus         | CPUs to use for handling traffic, default 'auto'
| Numa         | Numa node to use for traffic, default 'all'

Further information regarding the adqsetup tool that allows this configuration to be set can be found [here](https://pypi.org/project/adqsetup/)

If you edit this cofiguration while the ADQ CNI/DP pods are already deployed, you must restart the ADQ pods in order for them to pick up on the altered configuration

```sh
kubectl delete -n kube-system daemonset.apps/adq-cni-dp
kubectl apply -f deploy/k8s/adq-cluster-config.yaml
kubectl apply -f deploy/k8s/adq-cni-dp-ds.yaml
```

### TC/Queue Configuration

ADQ allows you to set the number of traffic classes you would like and the number of queues per traffic class. We can dynamically set this in /deploy/k8s/adq-cluster-config.yaml. The default configuration has 6 traffic classes. The first is the default traffic class 0, that all other non ADQ traffic will flow through. The default traffic class has 16 queues. There are 4 queues allocated to the each of the next 4 traffic classes in exclusive mode. The final traffic class has 32 queues and is in shared mode. The last traffic class must always be left to shared mode and the first must always be left as default. The default behaviour is independent polling with 4 pollers per TrafficClass.

### Independent poller configuration

Independent poller (ipoller) allows for a single independent poller to poll multiple queues. This means that ipoller does not have to be single application specific. To set ipoller mode across the cluster edit /deploy/k8s/adq-cluster-config.yaml to at a minimum include the number of "Pollers" you would like per TrafficClass. You can further fine tune the polling mode using the parameters listed above. An advantage of ipoller is that you are able to set per-TC value to configure poller timeout.
