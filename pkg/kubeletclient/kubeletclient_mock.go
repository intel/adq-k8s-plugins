// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation

package kubeletclient

import (
	"encoding/json"

	v1 "k8s.io/api/core/v1"
	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"
)

type KubeletClientMock struct {
	ResourceMap         []*ResourceInfo
	PodResources        []*podresourcesapi.PodResources
	GetResourceMapErr   error
	GetPodListErr       error
	SyncPodResourcesErr error

	AdqConfig       []*AdqConfigEntry
	GetAdqConfigErr error
}

func (kcm *KubeletClientMock) GetPodResourceMap(podName string, podNamespace string,
	master string) ([]*ResourceInfo, error) {
	return kcm.ResourceMap, kcm.GetResourceMapErr
}

func (kcm *KubeletClientMock) GetAdqConfig(podName string,
	podNamespace string) ([]*AdqConfigEntry, error) {
	return kcm.AdqConfig, kcm.GetAdqConfigErr
}

func (kcm *KubeletClientMock) GetPodList() (*v1.PodList, error) {
	podList := &v1.PodList{}
	pod := GenerateFakePod()
	podList.Items = append(podList.Items, *pod)
	return podList, kcm.GetPodListErr
}

func (kcm *KubeletClientMock) GetPodResources() []*podresourcesapi.PodResources {
	return kcm.PodResources
}

func (kcm *KubeletClientMock) SyncPodResources() error {
	return kcm.SyncPodResourcesErr
}

func GenerateFakePod() *v1.Pod {
	b := []byte(adqContainerDump)
	pod := &v1.Pod{}
	_ = json.Unmarshal(b, pod)
	return pod
}

const adqContainerDump = `
{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {
        "annotations": {
            "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{\"net.v1.intel.com/adq-config\":\"[ { \\\"name\\\": \\\"redis\\\", \\\"ports\\\": { \\\"local\\\": [\\\"6379/TCP\\\"] } } ]\"},\"name\":\"redis\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"command\":[\"redis-server\",\"/redis-master/redis.conf\"],\"image\":\"redis:5.0.4\",\"name\":\"redis\",\"ports\":[{\"containerPort\":6379}],\"resources\":{\"limits\":{\"net.intel.com/adq\":1}},\"volumeMounts\":[{\"mountPath\":\"/redis-master-data\",\"name\":\"data\"},{\"mountPath\":\"/redis-master\",\"name\":\"config\"}]}],\"nodeSelector\":{\"kubernetes.io/hostname\":\"silpixa00401197c\"},\"restartPolicy\":\"Never\",\"volumes\":[{\"emptyDir\":{},\"name\":\"data\"},{\"configMap\":{\"items\":[{\"key\":\"redis-config\",\"path\":\"redis.conf\"}],\"name\":\"example-redis-config\"},\"name\":\"config\"}]}}\n",
            "net.v1.intel.com/adq-config": "[ { \"name\": \"redis\", \"ports\": { \"local\": [\"6379/TCP\"] } } ]"
        },
        "creationTimestamp": "2022-03-04T11:30:18Z",
        "name": "redis",
        "namespace": "default",
        "resourceVersion": "10202055",
        "uid": "d801b01b-666c-4973-8e19-590e7cf8a273"
    },
    "spec": {
        "containers": [
            {
                "command": [
                    "redis-server",
                    "/redis-master/redis.conf"
                ],
                "image": "redis:5.0.4",
                "imagePullPolicy": "IfNotPresent",
                "name": "redis",
                "ports": [
                    {
                        "containerPort": 6379,
                        "protocol": "TCP"
                    }
                ],
                "resources": {
                    "limits": {
                        "net.intel.com/adq": "1"
                    },
                    "requests": {
                        "net.intel.com/adq": "1"
                    }
                },
                "terminationMessagePath": "/dev/termination-log",
                "terminationMessagePolicy": "File",
                "volumeMounts": [
                    {
                        "mountPath": "/redis-master-data",
                        "name": "data"
                    },
                    {
                        "mountPath": "/redis-master",
                        "name": "config"
                    },
                    {
                        "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                        "name": "kube-api-access-qdbn7",
                        "readOnly": true
                    }
                ]
            }
        ],
        "dnsPolicy": "ClusterFirst",
        "enableServiceLinks": true,
        "nodeName": "silpixa00401197c",
        "nodeSelector": {
            "kubernetes.io/hostname": "silpixa00401197c"
        },
        "preemptionPolicy": "PreemptLowerPriority",
        "priority": 0,
        "restartPolicy": "Never",
        "schedulerName": "default-scheduler",
        "securityContext": {},
        "serviceAccount": "default",
        "serviceAccountName": "default",
        "terminationGracePeriodSeconds": 30,
        "tolerations": [
            {
                "effect": "NoExecute",
                "key": "node.kubernetes.io/not-ready",
                "operator": "Exists",
                "tolerationSeconds": 300
            },
            {
                "effect": "NoExecute",
                "key": "node.kubernetes.io/unreachable",
                "operator": "Exists",
                "tolerationSeconds": 300
            }
        ],
        "volumes": [
            {
                "emptyDir": {},
                "name": "data"
            },
            {
                "configMap": {
                    "defaultMode": 420,
                    "items": [
                        {
                            "key": "redis-config",
                            "path": "redis.conf"
                        }
                    ],
                    "name": "example-redis-config"
                },
                "name": "config"
            },
            {
                "name": "kube-api-access-qdbn7",
                "projected": {
                    "defaultMode": 420,
                    "sources": [
                        {
                            "serviceAccountToken": {
                                "expirationSeconds": 3607,
                                "path": "token"
                            }
                        },
                        {
                            "configMap": {
                                "items": [
                                    {
                                        "key": "ca.crt",
                                        "path": "ca.crt"
                                    }
                                ],
                                "name": "kube-root-ca.crt"
                            }
                        },
                        {
                            "downwardAPI": {
                                "items": [
                                    {
                                        "fieldRef": {
                                            "apiVersion": "v1",
                                            "fieldPath": "metadata.namespace"
                                        },
                                        "path": "namespace"
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        ]
    },
    "status": {
        "conditions": [
            {
                "lastProbeTime": null,
                "lastTransitionTime": "2022-03-04T11:30:18Z",
                "status": "True",
                "type": "Initialized"
            },
            {
                "lastProbeTime": null,
                "lastTransitionTime": "2022-03-04T11:30:21Z",
                "status": "True",
                "type": "Ready"
            },
            {
                "lastProbeTime": null,
                "lastTransitionTime": "2022-03-04T11:30:21Z",
                "status": "True",
                "type": "ContainersReady"
            },
            {
                "lastProbeTime": null,
                "lastTransitionTime": "2022-03-04T11:30:18Z",
                "status": "True",
                "type": "PodScheduled"
            }
        ],
        "containerStatuses": [
            {
                "containerID": "containerd://d541163fd6500ac65ad4b168f25407b8a65199ac5ec54d389b84f159051566d4",
                "image": "docker.io/library/redis:5.0.4",
                "imageID": "docker.io/library/redis@sha256:2dfa6432744659268d001d16c39f7be52ee73ef7e1001ff80643f0f7bdee117e",
                "lastState": {},
                "name": "redis",
                "ready": true,
                "restartCount": 0,
                "started": true,
                "state": {
                    "running": {
                        "startedAt": "2022-03-04T11:30:21Z"
                    }
                }
            }
        ],
        "hostIP": "192.168.111.8",
        "phase": "Running",
        "podIP": "10.244.0.10",
        "podIPs": [
            {
                "ip": "10.244.0.10"
            }
        ],
        "qosClass": "BestEffort",
        "startTime": "2022-03-04T11:30:18Z"
    }
}
`
