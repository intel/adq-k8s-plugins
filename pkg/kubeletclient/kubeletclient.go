// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation

package kubeletclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/intel/adq-device-plugin/pkg/netlinktc"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"
	"k8s.io/kubernetes/pkg/kubelet/apis/podresources"
	"k8s.io/kubernetes/pkg/kubelet/util"
)

const (
	defaultADQHostnamePath = "/etc/cni/net.d/adq-cni.d/hostname"

	kubeletPodResourcePath = "/var/lib/kubelet/pod-resources"

	AdqResourceName       = "net.intel.com/adq"
	AdqSharedResourceName = "net.intel.com/adq-shared"

	adqConfigAnnotation = "net.v1.intel.com/adq-config"
	adqConfigSepartor   = "/"

	kubeletServerPortDefault = "10250"
	kubeletCACertPathDefault = "/var/lib/kubelet/pki/kubelet.crt"
)

var (
	kubeletSocket            string
	defaultADQKubeConfigPath = "/etc/cni/net.d/adq-cni.d/adq.kubeconfig"
	adqtcInit                = netlinktc.Init
)

type KubeletClient interface {
	GetPodResourceMap(podName string, podNamespace string, master string) ([]*ResourceInfo, error)
	GetPodResources() []*podresourcesapi.PodResources
	GetAdqConfig(podName string, podNamespace string) ([]*AdqConfigEntry, error)
	GetPodList() (*v1.PodList, error)
	SyncPodResources() error
}

type Port struct {
	ContainerPort int32               `json:"containerPort"`
	Protocol      string              `json:"protocol"`
	Direction     netlinktc.Direction `json:"direction"`
}

type ResourceInfo struct {
	TC                string `json:"tc,omitempty"`
	ContainerName     string `json:"containerName,omitempty"`
	LocalPorts        []Port `json:"localPorts,omitempty"`
	RemotePorts       []Port `json:"remotePorts,omitempty"`
	SingleQueueNumber string `json:"singleQueueNumber,omitempty"`
}

type kubeletHTTPClient struct {
	kubeletServerAddr string
	client            http.Client
	token             string
}

type kubeletClient struct {
	resources  []*podresourcesapi.PodResources
	httpClient *kubeletHTTPClient
}

type AdqPortMapEntry struct {
	RemotePorts []string `json:"remote,omitempty"`
	LocalPorts  []string `json:"local,omitempty"`
}

type AdqConfigEntry struct {
	Name  string           `json:"name"`
	Ports *AdqPortMapEntry `json:"ports"`
}

func (rc *kubeletClient) getPodResources(client podresourcesapi.PodResourcesListerClient) error {
	logger := log.WithField("func", "getPodResources").WithField("pkg", "kubeletclient")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.List(ctx, &podresourcesapi.ListPodResourcesRequest{})
	if err != nil {
		logger.Errorf("Failed to list pod resources for client: %v", client)
		return err
	}

	rc.resources = resp.PodResources
	return nil
}

func (rc *kubeletClient) GetPodResources() []*podresourcesapi.PodResources {
	return rc.resources
}

func GetKubeletClient(enableHTTPClient bool, ksName, ksPort, caPath string) (KubeletClient, error) {
	logger := log.WithField("func", "GetKubeletClient").WithField("pkg", "kubeletclient")
	newClient := &kubeletClient{}
	var err error
	if kubeletSocket == "" {
		kubeletSocket, _ = util.LocalEndpoint(kubeletPodResourcePath, podresources.Socket)
	}

	client, conn, err := podresources.GetV1Client(kubeletSocket, 10*time.Second, 1024*1024*16)
	if err != nil {
		logger.Error("Failed to get grpc client")
		return nil, err
	}
	defer conn.Close()

	if err := newClient.getPodResources(client); err != nil {
		logger.Error("Failed to get pod resources from client")
		return nil, err
	}

	if enableHTTPClient {
		hc, err := GetKubeletHTTPClient(ksName, ksPort, caPath)
		if err != nil {
			logger.Error("Failed to get kubelet http client")
			return nil, err
		}
		newClient.httpClient = hc
	}
	return newClient, nil
}

func getSingleQueueTC(master string) (string, error) {
	logger := log.WithField("func", "getSingleQueueTC").WithField("pkg", "kubeletclient")
	object, err := adqtcInit(master, false)
	if err != nil {
		logger.Error("Cannot initialize tc module")
		return "", err
	}

	sharedTCNumber, err := object.GetSharedTC()
	if err != nil {
		logger.Error("Failed to get shared TC")
		return "", err
	}

	return strconv.Itoa(int(sharedTCNumber)), nil
}

func (rc *kubeletClient) GetPodResourceMap(podName string, podNamespace string, master string) ([]*ResourceInfo, error) {
	logger := log.WithField("func", "GetPodResourceMap").WithField("pkg", "kubeletclient")
	result := make([]*ResourceInfo, 0)
	for _, pr := range rc.resources {
		if podName == pr.GetName() && podNamespace == pr.GetNamespace() {
			cs := pr.GetContainers()
			for _, c := range cs {
				for _, d := range c.Devices {
					logger.Infof("Found Pod %s resource %s with value %s", podName, d.ResourceName, d.DeviceIds[0])
					if AdqResourceName == d.ResourceName {
						// there can be only one for the container
						resourceInfo := &ResourceInfo{}
						resourceInfo.TC = d.DeviceIds[0]
						resourceInfo.ContainerName = c.GetName()
						result = append(result, resourceInfo)
					}
					// it can be single queue tc request
					if AdqSharedResourceName == d.ResourceName {
						tc, err := getSingleQueueTC(master)
						if err != nil {
							logger.Errorf("Cannot get tc for single queue config: %v", err)
							continue
						}
						resourceInfo := &ResourceInfo{}
						resourceInfo.SingleQueueNumber = d.DeviceIds[0]
						resourceInfo.TC = tc
						resourceInfo.ContainerName = c.GetName()
						result = append(result, resourceInfo)
					}
				}
			}
		}
	}
	if len(result) == 0 {
		logger.Errorf("No %s or %s resources were found in pod %s", AdqResourceName, AdqSharedResourceName, podName)
		return nil, fmt.Errorf("getPodResourceMap did not find %s or %s resources in pod %s", AdqResourceName, AdqSharedResourceName, podName)
	}

	return result, nil
}

func getHostname(path string) (string, error) {
	logger := log.WithField("func", "getHostname").WithField("pkg", "kubeletclient")
	hf, err := os.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed to get hostname from %v file", path)
		return "", err
	}
	if len(hf) == 0 {
		return "", fmt.Errorf("missing hostname in %v file", path)
	}

	return string(hf), nil
}

func GetKubeletHTTPClient(ksName, ksPort, caPath string) (*kubeletHTTPClient, error) {
	logger := log.WithField("func", "GetKubeletHTTPClient").WithField("pkg", "kubeletclient")
	serverName := ksName
	var err error
	if serverName == "" {
		serverName, err = getHostname(defaultADQHostnamePath)
		if err != nil {
			return nil, err
		}
	}

	serverPort := ksPort
	if serverPort == "" {
		serverPort = kubeletServerPortDefault
	}

	serverCACertPath := caPath
	if serverCACertPath == "" {
		serverCACertPath = kubeletCACertPathDefault
	}

	caCert, err := ioutil.ReadFile(serverCACertPath)
	if err != nil {
		logger.Errorf("Failed to read file with server CA Cert")
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caCert)
	if !ok {
		logger.Error("Unable to load CA cert into pool")
		return nil, fmt.Errorf("unable to load CA cert into pool")
	}

	config, err := clientcmd.LoadFromFile(defaultADQKubeConfigPath)
	if err != nil {
		logger.Errorf("Unable to load kubeconfig from %v file", defaultADQKubeConfigPath)
		return nil, err
	}

	if len(config.AuthInfos) == 0 {
		return nil, fmt.Errorf("authInfos map empty")
	}

	var t string
	for _, val := range config.AuthInfos {
		if val != nil {
			t = val.Token
			break
		}
	}

	return &kubeletHTTPClient{
		kubeletServerAddr: "https://" + serverName + ":" + serverPort,
		client: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				}},
			Timeout: 30 * time.Second,
		},
		token: t,
	}, nil
}

func (khc *kubeletHTTPClient) GetPodList() (*v1.PodList, error) {
	logger := log.WithField("func", "GetPodList").WithField("pkg", "kubeletclient")

	url := khc.kubeletServerAddr + "/pods"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logger.Errorf("Unable to create new GET request for %v", url)
		return nil, err
	}

	header := http.Header{}
	header.Add("Authorization", "bearer "+khc.token)
	req.Header = header

	resp, err := khc.client.Do(req)
	if err != nil {
		logger.Errorf("Error when calling request:%v", req)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, e := io.ReadAll(resp.Body)
		if e != nil {
			body = []byte("Read body error: " + e.Error())
		}
		logger.Errorf("HTTP resp status:%v, body:%v", resp.StatusCode, string(body))
		return nil, fmt.Errorf("HTTP resp status: %d, req URL: %s", resp.StatusCode, req.URL.String())
	}

	pl := &v1.PodList{}
	d := json.NewDecoder(resp.Body)

	err = d.Decode(pl)
	if err != nil {
		body, e := io.ReadAll(resp.Body)
		if e != nil {
			body = []byte("Read body error: " + e.Error())
		}
		logger.Errorf("Error when decoding pod list from response:%v for request: %v", string(body), req)
		return nil, err
	}
	return pl, nil
}

func (khc *kubeletHTTPClient) GetPod(namespace, podName string) (*v1.Pod, error) {
	logger := log.WithField("func", "GetPod").WithField("pkg", "kubeletclient")
	pl, err := khc.GetPodList()
	if err != nil {
		logger.Error("Failed to get pod list")
		return nil, err
	}

	for _, p := range pl.Items {
		if p.Namespace == namespace && p.Name == podName {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("pod name:%v in namespace:%v does not exist", podName, namespace)
}

func (kc *kubeletClient) GetAdqConfig(namespace, podName string) ([]*AdqConfigEntry, error) {
	logger := log.WithField("func", "GetAdqConfig").WithField("pkg", "kubeletclient")
	pod, err := kc.httpClient.GetPod(namespace, podName)
	if err != nil {
		logger.Error("Failed to get pod")
		return nil, err
	}

	var config []*AdqConfigEntry
	config, err = kc.httpClient.getAnnotationConfig(pod)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (kc *kubeletClient) GetPodList() (*v1.PodList, error) {
	return kc.httpClient.GetPodList()
}

func (khc *kubeletHTTPClient) getAnnotationConfig(pod *v1.Pod) ([]*AdqConfigEntry, error) {
	logger := log.WithField("func", "getAnnotationConfig").WithField("pkg", "kubeletclient")
	adqAnnotation := pod.GetAnnotations()[adqConfigAnnotation]
	// get object name
	logger.Debugf("Pods annotation %v", adqAnnotation)
	if len(adqAnnotation) == 0 {
		logger.Debugf("No ADQ annotation found")
		return nil, nil
	}

	var adqConfig []*AdqConfigEntry
	// check if we have conig json in pod spec
	if strings.ContainsAny(adqAnnotation, "[{\"") {
		if err := json.Unmarshal([]byte(adqAnnotation), &adqConfig); err != nil {
			logger.Errorf("Failed to unmarshall %v", adqAnnotation)
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("annotation with ADQ config not in JSON format %s", adqAnnotation)
	}

	return adqConfig, nil
}

func (rc *kubeletClient) SyncPodResources() error {
	logger := log.WithField("func", "SyncPodResources").WithField("pkg", "kubeletclient")
	var err error
	if kubeletSocket == "" {
		kubeletSocket, _ = util.LocalEndpoint(kubeletPodResourcePath, podresources.Socket)
	}

	client, conn, err := podresources.GetV1Client(kubeletSocket, 10*time.Second, 1024*1024*16)
	if err != nil {
		logger.Error("Failed to get grpc client")
		return err
	}
	defer conn.Close()

	if err := rc.getPodResources(client); err != nil {
		logger.Error("Failed to get pod resources from client")
		return err
	}
	return nil
}
