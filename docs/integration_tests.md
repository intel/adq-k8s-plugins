# ADQ in K8s Integration tests

**Test suite environment requirements**:

- Kubernetes Cluster:
  - 1 physical machine control node
  - 1 physical machine worker node
  - 2 CVL NICs
  - Back to back 100G connection between 2 nodes
  - Linux kernel 5.13.13 or newer
  - Deployed ADQ CNI and ADQ DP

**Test suite environment setup**:

Please follow the steps included in the [README.md](../README.md) file to set up the test environment.

**Other assumptions:**

- All commands are executed in project's root directory.

- tc tool is installed:

  on CentOS: `dnf install iproute-tc`

- Edit docs/redis-pod.yaml `hostname: <hostname>` to match your control node hostname.

- Apply redis-config.yaml required to run sample redis pod.

  ```sh
  kubectl apply -f docs/redis-config.yaml
  ```

- Replace `ens801f0` with your control node network interface name.

- After each test delete pods created during testing.

## **Device Plugin**

## Test 1: Device Plugin TCs are set correctly

Ensure that the the number of TCs (Traffic Classes) available are the same as the ones available on the node and have been set in the adqsetup tool during the ADQ cluster creation.

### Test steps

1. Run the command below to see all the queuing disciplines created.

   ```sh
   tc qdisc show dev ens801f0 | head -n4
   ```

   Expected output:

   ```text
   qdisc mqprio 8001: root tc 6 map 0 1 2 3 4 5 0 0 0 0 0 0 0 0 0 0
             queues:(0:15) (16:19) (20:23) (24:27) (28:31) (32:63)
             mode:channel
             shaper:dcb
   ```

2. From the output of this command, compare the queues and TCs set to the configuration provided in [deploy/k8s/adq-cluster-config.yaml](../deploy/k8s/adq-cluster-config.yaml). In this example default traffic class TC0 has 16 queues (0:15), traffic classes TC1 to TC4 each have 4 queues (TC1 has 16:19, TC2 20:23, etc) and the last traffic class TC5 has 32 ADQ shared queues (32:63).

   ```text
   (0:31)  (32:35)(36:39)(40:43)(44:47)(48:51)(52:55)(56:59)(60:63)(64:79)
   ^TC0     ^TC1   ^TC2   ^TC3   ^TC4   ^TC5    ^TC6   ^TC7  ^TC8  ^TC9
   ^default ^adq-single--------------------------------------^     ^adq-shared
   ```

## Test 2: ADQ allocatable resources change when pods are deployed and deleted

Ensure that when a pod that uses an ADQ resource is created, either adq exclusive or adq shared, the number of ADQ resources that the device plugin sees as allocated is updated.

### Test steps

1. Record how many ADQ shared and exclusive resources are available on the system with the command below:

   ```sh
   kubectl get nodes -o json | jq '.items[].status.allocatable'
   ```

   Expected output:

   ```json
   {
     ...
     "net.intel.com/adq": "4", //adq-single
     "net.intel.com/adq-shared": "31",
     ...
   }
   {
     ...
     "net.intel.com/adq": "4", //adq-single
     "net.intel.com/adq-shared": "31",
     ...
   }
   ```

2. From the output of this command, compare what is set to what was configured in [../deploy/k8s/adq-cluster-config.yaml](../deploy/k8s/adq-cluster-config.yaml). Last traffic class has one less queue than requested beacause it is reserved by driver and will not be used.

3. Record how many net.intel.com/adq and net.intel.com/adq-shared resources are used with the command under the Allocated resources header. We can see here no ADQ resources are currently in use.

   ```sh
   kubectl describe node $(hostname)
   ```

   Expected output:

    ```sh
    Allocated resources:
      (Total limits may be over 100 percent, i.e., overcommitted.)
      Resource                  Requests     Limits
      --------                  --------     ------
      cpu                       8542m (3%)   8610m (3%)
      memory                    3128Mi (4%)  2828Mi (4%)
      ephemeral-storage         0 (0%)       0 (0%)
      hugepages-1Gi             0 (0%)       0 (0%)
      hugepages-2Mi             0 (0%)       0 (0%)
      net.intel.com/adq         0            0
      net.intel.com/adq-shared  0            0
    ```

4. Deploy a sample pod with the podspec below to test ADQ exclusive functionality.

   ```sh
   kubectl apply -f docs/redis-pod.yaml
   ```

5. Inspect deployed pod to ensure it is deployed correctly.

   ```sh
   kubectl get pods
   ```

6. Run the command again and see if the amount of ADQ exclusive resources allocated has been increased by 1.

   ```sh
   kubectl describe node $(hostname)
   ```

   Expected output:

   ```sh
   Allocated resources:
     (Total limits may be over 100 percent, i.e., overcommitted.)
     Resource                  Requests     Limits
     --------                  --------     ------
     cpu                       8542m (3%)   8610m (3%)
     memory                    3128Mi (4%)  2828Mi (4%)
     ephemeral-storage         0 (0%)       0 (0%)
     hugepages-1Gi             0 (0%)       0 (0%)
     hugepages-2Mi             0 (0%)       0 (0%)
     net.intel.com/adq         1            1
     net.intel.com/adq-shared  0            0
   ```

7. Edit the sample pod spec to test the ADQ shared functionality. Alter the lines below as follows:

   ```sh
   4      name: redis-shared
   .
   .
   20           net.intel.com/adq-shared: 1
   ```

8. Deploy the second sample pod to test ADQ shared functionality.

   ```sh
   kubectl apply -f docs/redis-pod.yaml
   ```

9. Inspect deployed pod to ensure it is deployed correctly.

   ```sh
   kubectl get pods
   ```

10. Run the command again and see if the amount of ADQ shared resources allocated has been increased by 1.

   ```sh
   kubectl describe node $(hostname)
   ```

   Expected output:

   ```sh
   Allocated resources:
     (Total limits may be over 100 percent, i.e., overcommitted.)
     Resource                  Requests     Limits
     --------                  --------     ------
     cpu                       8542m (3%)   8610m (3%)
     memory                    3128Mi (4%)  2828Mi (4%)
     ephemeral-storage         0 (0%)       0 (0%)
     hugepages-1Gi             0 (0%)       0 (0%)
     hugepages-2Mi             0 (0%)       0 (0%)
     net.intel.com/adq         1            1
     net.intel.com/adq-shared  1            1
   ```

## Test 3: Ingress traffic filters are correct

Ensure that the the ingress traffic filters are correct.

### Test steps

1. Deploy a sample pod as seen below to test ingress filters with ADQ exclusive functionality.

   ```sh
   kubectl apply -f docs/redis-pod.yaml
   ```

2. Inspect deployed pod to ensure it is deployed correctly.

   ```sh
   kubectl get pods
   ```

3. Run the command below to display all ingress filters on the interface.

   ```sh
   tc filter show dev ens801f0 ingress
   ```

   Expected output:

   `filter protocol ip pref` should match `FilterPrio` in [deploy/k8s/adq-cluster-config.yaml](../deploy/k8s/adq-cluster-config.yaml).

   `dest_ip` should match the ip of the pod we deployed.

   `hw_tc` is traffic class assigned by plugin.

   `dst_port` and `ip_proto` are set in pod yaml.

   ```sh
   filter protocol ip pref 1 flower chain 0
   filter protocol ip pref 1 flower chain 0 handle 0x1 hw_tc 4
     eth_type ipv4
     ip_proto tcp
     dst_ip 10.244.0.234
     dst_port 6379
     skip_sw
     in_hw in_hw_count 1
   ```

4. Edit the sample pod spec to now test the ADQ shared functionality. Alter the lines below as follows:

   ```yaml
   4      name: redis-shared
   ...
   20           net.intel.com/adq-shared: 1
   ```

5. Deploy the second sample pod to test ingress filters with ADQ shared functionality.

   ```sh
   kubectl apply -f docs/redis-pod.yaml
   ```

6. Inspect deployed pod to ensure it is deployed correctly.

   ```sh
   kubectl get pods
   ```

7. Display all ingress filters on the interface.

   ```sh
   tc filter show dev ens801f0 ingress
   ```

   Expected output:

   Note that adq-shared pod has `classid` instead of `hw_tc`.

   ```sh
   filter protocol ip pref 1 flower chain 0
   filter protocol ip pref 1 flower chain 0 handle 0x1 hw_tc 4
     eth_type ipv4
     ip_proto tcp
     dst_ip 10.244.0.234
     dst_port 6379
     skip_sw
     in_hw in_hw_count 1
   filter protocol ip pref 1 flower chain 0 handle 0x2 classid ffff:28
     eth_type ipv4
     ip_proto tcp
     dst_ip 10.244.0.35
     dst_port 6379
     skip_sw
     in_hw in_hw_count 1
   ```

## Test 4: Netprio or Egress traffic filters are correct

Ensure that egress traffic filters with skbedit are correct. (default)
Or ensure that the the priorities of the egress traffic are correctly configured. (netprio)

### Test steps

1. Deploy a sample pod as seen below.

   ```sh
   kubectl apply -f docs/redis-pod.yaml
   ```

2. Inspect deployed pod to ensure it is deployed correctly.

   ```sh
   kubectl get pods
   ```

- If using egress filters:

1. Display all egress filters on interface.

   ```sh
   tc filter show dev ens801f0 egress
   ```

   Expected output:

   `skbedit  priority` should match `hw_tc` number from ingress filter, in this case 4.

   ```text
   filter protocol ip pref 1 flower chain 0
   filter protocol ip pref 1 flower chain 0 handle 0x1
     eth_type ipv4
     ip_proto tcp
     src_ip 10.244.0.234
     src_port 6379
     not_in_hw
           action order 1: skbedit  priority :4 pipe
            index 1 ref 1 bind 1
   ```

- If using netprio:

1. Get the container ID from the pod description.

   Expected output sample:

   ```sh
   kubectl describe pod redis | grep Container\ ID
   ```

2. Look at the egress priority set for the master interface in the file net_prio.ifpriomap in sysfs.

   ```sh
   cat /sys/fs/cgroup/net_prio/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod*/crio-<sample pod container id>.scope/net_prio.ifpriomap
   ```

   Expected output:

   Value for priority may change but it will not be 0, and it should match `hw_tc` in ingress filter, in this case 8.

   ```text
   lo 0
   ens801f0 8
   eno1 0
   ens801f1 0
   eno2 0
   docker0 0
   cilium_host 0
   ```

## TEST 5: ADQ configuration persists after reboot

Ensure that the ADQ configurations persist after a node goes down for a period of time.

### Test steps

1. Deploy a sample pod with the podspec below.

   ```sh
   kubectl apply -f docs/redis-pod.yaml
   ```

2. Inspect deployed pod to ensure it is deployed correctly.

   ```sh
   kubectl get pods
   ```

3. Reboot the control node.

   ```sh
   reboot
   ```

   Complete any further steps to get the cluster up again.

4. Watch to see if the ADQ pods restart successfully.

   ```sh
   kubectl get pods
   ```

   Pod redis should be in running state.

5. Ensure that the qdiscs are still set correctly.

   ```sh
   tc qdisc show dev ens801f0 | head -n4
   ```

   Expected output:

   ```text
   qdisc mqprio 8001: root tc 6 map 0 1 2 3 4 5 0 0 0 0 0 0 0 0 0 0
                queues:(0:15) (16:19) (20:23) (24:27) (28:31) (32:63)
                mode:channel
                shaper:dcb
   ```

6. Ensure that the filters are still set correctly.

   ```sh
   tc filter show dev ens801f0 ingress
   ```

   ```text
   filter protocol ip pref 1 flower chain 0
   filter protocol ip pref 1 flower chain 0 handle 0x1 hw_tc 4
     eth_type ipv4
     ip_proto tcp
     dst_ip 10.244.0.135
     dst_port 6379
     skip_sw
     in_hw in_hw_count 1
   ```

   ```sh
   tc filter show dev ens801f0 egress
   ```

   ```text
   filter protocol ip pref 1 flower chain 0
   filter protocol ip pref 1 flower chain 0 handle 0x1
     eth_type ipv4
     ip_proto tcp
     src_ip 10.244.0.135
     src_port 6379
     not_in_hw
           action order 1: skbedit  priority :4 pipe
            index 1 ref 1 bind 1
   ```

## Test 6: No value in net.v1.intel.com/adq-config in pod spec

Ensure that if no value in net.v1.intel.com/adq-config under annotation is given to the pod spec it will default to accelerating all ports on the pod connected to the pod ip.

### Test steps

1. Alter line 6 in the redis pod spec above to leave no ADQ annotations as shown below:

   ```yaml
   net.v1.intel.com/adq-config: ''
   ```

2. Deploy the pod.

   ```sh
   kubectl apply -f docs/redis-pod.yaml
   ```

3. Inspect deployed pod and verify that pod is running.

   ```sh
   kubectl get pods
   ```

4. Run the command below to display all ingress filters on the interface to ensure the filters are set correctly.

   ```sh
   tc filter show dev ens801f0 ingress
   ```

   Expected output:

   Note no `dst_port` in both filters.

   ```text
   filter protocol ip pref 1 flower chain 0
   filter protocol ip pref 1 flower chain 0 handle 0x2 hw_tc 1
     eth_type ipv4
     dst_ip 10.244.0.237
     skip_sw
     in_hw in_hw_count 1
   ```

   ```sh
   tc filter show dev ens801f0 egress
   ```

   ```text
   filter protocol ip pref 1 flower chain 0
   filter protocol ip pref 1 flower chain 0 handle 0x2
     eth_type ipv4
     src_ip 10.244.0.237
     not_in_hw
           action order 1: skbedit  priority :1 pipe
            index 2 ref 1 bind 1
   ```

5. Verify that 1 ADQ resource has been allocated to this pod. Replace `$(hostname)` with the name of the server if necessary.

   ```sh
   kubectl describe node $(hostname)
   ```

   Expected output:

   ```text
   Allocated resources:
     (Total limits may be over 100 percent, i.e., overcommitted.)
     Resource                  Requests     Limits
     --------                  --------     ------
     cpu                       8542m (3%)   8610m (3%)
     memory                    3128Mi (4%)  2828Mi (4%)
     ephemeral-storage         0 (0%)       0 (0%)
     hugepages-1Gi             0 (0%)       0 (0%)
     hugepages-2Mi             0 (0%)       0 (0%)
     net.intel.com/adq         1            1
     net.intel.com/adq-shared  0            0
   ```

## Test 7: No annotation in pod spec

Ensure that if no annotation is given to the pod spec it will default to accelerating all ports on the pod connected to the pod ip.

### Test steps

1. Delete line 6 in the redis pod spec above to leave no annotations as shown below:

   ```yaml
   5      annotations:
   6    spec:
   ```

2. Deploy the pod.

   ```sh
   kubectl apply -f docs/redis-pod.yaml
   ```

3. Inspect deployed pod and verify that pod is running.

   ```sh
   kubectl get pods
   ```

4. Run the command below to display all filters on the interface to ensure the filters are set correctly.

   ```sh
   tc filter show dev ens801f0 ingress
   ```

   ```text
   filter protocol ip pref 1 flower chain 0
   filter protocol ip pref 1 flower chain 0 handle 0x1 hw_tc 1
     eth_type ipv4
     dst_ip 10.244.0.205
     skip_sw
     in_hw in_hw_count 1
   ```

   ```sh
   tc filter show dev ens801f0 egress
   ```

   ```text
   filter protocol ip pref 1 flower chain 0
   filter protocol ip pref 1 flower chain 0 handle 0x1
     eth_type ipv4
     src_ip 10.244.0.205
     not_in_hw
           action order 1: skbedit  priority :1 pipe
            index 1 ref 1 bind 1
   ```

5. Verify that 1 ADQ resource has been allocated to this pod.

   ```sh
   kubectl describe node $hostname
   ```

   Expected output:

   ```text
   Allocated resources:
     (Total limits may be over 100 percent, i.e., overcommitted.)
     Resource                  Requests     Limits
     --------                  --------     ------
     cpu                       8542m (3%)   8610m (3%)
     memory                    3128Mi (4%)  2828Mi (4%)
     ephemeral-storage         0 (0%)       0 (0%)
     hugepages-1Gi             0 (0%)       0 (0%)
     hugepages-2Mi             0 (0%)       0 (0%)
     net.intel.com/adq         1            1
     net.intel.com/adq-shared  0            0
   ```

## Test 8: More than one port specified in pod spec annotation

Ensure that if more than one port is given in the annotation in the pod spec that all given ports are accelerated.

### Test steps

1. Have the ADQ deployment up and running according to the setup steps.

2. Alter line 6 in the redis pod spec above to specify more than one port as shown below

   ```yaml
   net.v1.intel.com/adq-config: '[ { "name": "redis", "ports": { "local": ["6379/  TCP", "6378/  TCP" ] } } ]'
   ```

3. Deploy the pod

   ```sh
   kubectl apply -f docs/redis-pod.yaml
   ```

4. Inspect deployed pod and verify that pod is up and running.

   ```sh
   kubectl get pods
   ```

5. Check that the filter is set correctly and both ports have filters set.

   ```sh
   tc filter show dev ens801f0 ingress
   ```

   Expected output:

   There will be 2 filters, 1 for each defined port.

   ```text
   filter protocol ip pref 1 flower chain 0
   filter protocol ip pref 1 flower chain 0 handle 0x1 hw_tc 1
     eth_type ipv4
     ip_proto tcp
     dst_ip 10.244.0.232
     dst_port 6379
     skip_sw
     in_hw in_hw_count 1
   filter protocol ip pref 1 flower chain 0 handle 0x2 hw_tc 1
     eth_type ipv4
     ip_proto tcp
     dst_ip 10.244.0.232
     dst_port 6300
     skip_sw
     in_hw in_hw_count 1
   ```

   ```sh
   tc filter show dev ens801f0 egress
   ```

   ```text
   filter protocol ip pref 1 flower chain 0
   filter protocol ip pref 1 flower chain 0 handle 0x1
     eth_type ipv4
     ip_proto tcp
     src_ip 10.244.0.232
     src_port 6379
     not_in_hw
           action order 1: skbedit  priority :1 pipe
            index 1 ref 1 bind 1

   filter protocol ip pref 1 flower chain 0 handle 0x2
     eth_type ipv4
     ip_proto tcp
     src_ip 10.244.0.232
     src_port 6300
     not_in_hw
           action order 1: skbedit  priority :1 pipe
            index 2 ref 1 bind 1
   ```

6. Verify that 1 ADQ resource has been allocated to this pod. Replace $hostname with the name of the control node.

```sh
kubectl describe node $hostname
```

Expected output:

```text
Allocated resources:
  (Total limits may be over 100 percent, i.e., overcommitted.)
  Resource                  Requests     Limits
  --------                  --------     ------
  cpu                       8542m (3%)   8610m (3%)
  memory                    3128Mi (4%)  2828Mi (4%)
  ephemeral-storage         0 (0%)       0 (0%)
  hugepages-1Gi             0 (0%)       0 (0%)
  hugepages-2Mi             0 (0%)       0 (0%)
  net.intel.com/adq         1            1
  net.intel.com/adq-shared  0            0
```

## Test 9: Unmarshallable pod spec annotation

Ensure that if incorrect syntax is used or illegal character are used in the annotation in the pod spec that causes it to be unmarshallable the pod fails to launch.

### Test steps

1. Alter the pod spec to include unmarshallable characters or invalid json format such as shown below on line 6.

   ```yaml
   net.v1.intel.com/adq-config: '[ { "redis", "ports": { "local": ["6379/  TCP"] } } ] '
   ```

2. Deploy the pod.

   ```sh
   kubectl apply -f docs/redis-pod.yaml
   ```

3. Inspect deployed pod.

   ```sh
   kubectl get pods
   kubectl describe pod redis
   ```

4. Verify that pod is stuck in ContainerCreating. Verify that the reason the pod is in ContainerCreating is due to the fact that the annotation cannot be read.

5. Verify that no filters have been set.

```sh
tc filter show dev ens801f0 ingress
tc filter show dev ens801f0 egress
```

## Test 10: 0 ADQ resources requested in pod spec

Ensure that if no ADQ rescources are requested in the pod spec then no filters are created and no ADQ resources are allocated, even if the annotation is present.

### Test steps

1. Alter line 20 in the redis pod spec above to specify no ADQ resources are being requested

   ```yaml
   18       resources:
   19         limits:
   20           net.intel.com/adq: 0
   ```

2. Deploy the pod

   ```sh
   kubectl apply -f docs/redis-pod.yaml
   ```

3. Verify that pod is created and running.

   ```sh
   kubectl get pods
   ```

4. Inspect the logs of the ADQ CNI to verify the error was caught

   ```sh
   less /var/log/adq-cni.log
   ```

   Logs should contain:

   `No net.intel.com/adq or net.intel.com/adq-shared resources were found in pod redis`

   and

   `Pod: redis in namespace default is not requesting adq`

5. Verify that no ADQ resource has been allocated to this pod. Replace $hostname with the name of the control node.

   ```sh
   kubectl describe node $hostname
   ```

   Expected output:

   ```text
   Allocated resources:
     (Total limits may be over 100 percent, i.e., overcommitted.)
     Resource                  Requests     Limits
     --------                  --------     ------
     cpu                       8542m (3%)   8610m (3%)
     memory                    3128Mi (4%)  2828Mi (4%)
     ephemeral-storage         0 (0%)       0 (0%)
     hugepages-1Gi             0 (0%)       0 (0%)
     hugepages-2Mi             0 (0%)       0 (0%)
     net.intel.com/adq         0            0
     net.intel.com/adq-shared  0            0
   ```

6. Verify no filters were created for the pod.

   ```sh
   tc filter show dev ens801f0 ingress
   tc filter show dev ens801f0 egress
   ```

## Test 11: Unique node configurations for each node

Ensure that each node uses the correct node configuration from adq-cluster-config.

### Test steps

1. Label the nodes with two unique labels:

   ```sh
   kubectl label node master0 test=labelA
   kubectl label node worker0 test=labelB
   ```

2. Update `adq-cluster-config.yaml` to have two different node configs with

   ```json
   "Labels": {
      "test": "labelA"
   },
   ```

   and

   ```json
   "Labels": {
      "test": "labelB"
   },
   ```

   Additionally change one of the node configs body, (for example number of traffic classes) to verify if matched node config was used to render adqsetup configuration.
3. Apply new `adq-cluster-config.yaml` to cluster.
4. Redeploy `adq-cni-dp`
5. Inspect `/etc/cni/net.d/adq-cni.d/node-config` on both nodes if correct one was matched
6. Inspect logs of adqsetup containers

   ```sh
   kubectl logs -n kube-system -c adqsetup adq-cni-dp-xxxxx
   ```

   and check rendered configs against node configs from `/etc/cni/net.d/adq-cni.d/node-config`.

## Test 12: Master interface discovery and override

Ensure that master interface on each node is correctly discovered if it's not specified in node configuration and configured one is used otherwise.

### Test steps

1. Edit `adq-cluster-config.yaml` and remove `Dev: ensXXXXX` from `Globals` if specified. Apply yaml to the cluster.
2. Redeploy `adq-cni-dp`
3. Check IP addresses of the nodes:

   ```sh
   kubectl describe node master0 | grep InternalIP
   ```

   and

   ```sh
   kubectl describe node worker0 | grep InternalIP
   ```

4. On both nodes, check which interface has the IP address from the previous step and compare it against `/etc/cni/net.d/adq-cni.d/node-config`

   ```json
   "Globals": 
   {
      ...               
      "Dev": "ens801f0",
      ...         
   }, 
   ```

5. Inspect logs of adqsetup container

   ```sh
   kubectl logs -n kube-system -c adqsetup adq-cni-dp-xxxxx
   ```

   and check if the same interfaces were used.

   ```sh
   ** configuration **                               
   [globals]

   ...    
   dev = ens801f0
   ...

   ```

6. Edit `adq-cluster-config.yaml` again and modify `Globals.Dev` to some invalid interface name eg. `ensABC0`.
7. Redeploy `adq-cni-dp` again - pods should now fail to start
8. Inspect `/etc/cni/net.d/adq-cni.d/node-config` again and check if the interface name was overridden correctly.
9. Inspect logs of adqsetup container and check if `ensABC0` was used for the (failed) configuration attempts
