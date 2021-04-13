// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation

package kubeletclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/intel/adq-device-plugin/pkg/netlinktc"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"
	"k8s.io/kubernetes/pkg/kubelet/apis/podresources"
	"k8s.io/kubernetes/pkg/kubelet/util"
)

func TestKubeletClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "kubeletclient Test Suite")
}

func AdqTCInit(ifname string, virtual bool) (netlinktc.NetlinkTc, error) {
	adqm.InitMaster = ifname
	return adqm, nil
}

var (
	rsMock            *resourceServerMock
	rsMockTempdir     string
	kubeletSocketMock string

	certTempDir string

	adqm *netlinktc.NetlinkTcMock
)

var _ = BeforeSuite(func() {
	var err error
	certTempDir, err = ioutil.TempDir("", "kubeletclient-CA")
	Expect(err).ToNot(HaveOccurred())

	caKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	Expect(err).ToNot(HaveOccurred())

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"kubeletclienttest"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &caKey.PublicKey, caKey)
	Expect(err).ToNot(HaveOccurred())

	pemcert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	err = os.WriteFile(path.Join(certTempDir, "ca.pem"), pemcert, 0644)
	Expect(err).ToNot(HaveOccurred())

	b, err := x509.MarshalECPrivateKey(caKey)
	Expect(err).ToNot(HaveOccurred())
	pemkey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	err = os.WriteFile(path.Join(certTempDir, "key.pem"), pemkey, 0644)
	Expect(err).ToNot(HaveOccurred())

	// kubeconfig
	cfg := clientcmdapi.Config{
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"test": {
				Token: "sometoken-not-validated-by-fake-kubelet-server",
			},
		},
	}
	err = clientcmd.WriteToFile(cfg, path.Join(certTempDir, "kubeconfig"))
	Expect(err).ToNot(HaveOccurred())

	defaultADQKubeConfigPath = path.Join(certTempDir, "kubeconfig")

})

var _ = AfterSuite(func() {
	err := os.RemoveAll(certTempDir)
	Expect(err).ToNot(HaveOccurred())
})

var _ = BeforeEach(func() {
	// pod resource server
	rsMock = &resourceServerMock{server: grpc.NewServer()}
	podresourcesapi.RegisterPodResourcesListerServer(rsMock.server, rsMock)

	rsMockTempdir, err := ioutil.TempDir("", "kubeletclient")
	Expect(err).ToNot(HaveOccurred())

	kubeletSocketMock, err = util.LocalEndpoint(rsMockTempdir, podresources.Socket)
	Expect(err).ToNot(HaveOccurred())

	listener, err := util.CreateListener(kubeletSocketMock)
	Expect(err).ToNot(HaveOccurred())

	kubeletSocket = kubeletSocketMock
	go func() {
		defer GinkgoRecover()
		Eventually(func() error { return rsMock.server.Serve(listener) }, "10s", "1s").ShouldNot(HaveOccurred())
	}()
})

var _ = AfterEach(func() {
	if rsMock != nil {
		rsMock.server.Stop()
	}

	err := os.RemoveAll(rsMockTempdir)
	Expect(err).ToNot(HaveOccurred())
})

type resourceServerMock struct {
	server       *grpc.Server
	podResources []*podresourcesapi.PodResources
	err          error
}

func (rsm *resourceServerMock) List(ctx context.Context,
	in *podresourcesapi.ListPodResourcesRequest) (*podresourcesapi.ListPodResourcesResponse, error) {
	return &podresourcesapi.ListPodResourcesResponse{
		PodResources: rsm.podResources,
	}, rsm.err
}

func (rsm *resourceServerMock) GetAllocatableResources(ctx context.Context,
	in *podresourcesapi.AllocatableResourcesRequest) (*podresourcesapi.AllocatableResourcesResponse, error) {
	return &podresourcesapi.AllocatableResourcesResponse{}, nil
}

func generatePodResources() []*podresourcesapi.PodResources {
	return []*podresourcesapi.PodResources{
		{
			Name:      "testpod1",
			Namespace: "default",
			Containers: []*podresourcesapi.ContainerResources{
				{
					Name: "container1",
					Devices: []*podresourcesapi.ContainerDevices{
						{
							ResourceName: "someresource1",
							DeviceIds:    []string{"1"},
						},
					},
				},
				{
					Name: "container2",
					Devices: []*podresourcesapi.ContainerDevices{
						{
							ResourceName: "someresource2",
							DeviceIds:    []string{"2"},
						},
					},
				},
			},
		},
		{
			Name:      "testpod2",
			Namespace: "default",
			Containers: []*podresourcesapi.ContainerResources{
				{
					Name: "container1",
					Devices: []*podresourcesapi.ContainerDevices{
						{
							ResourceName: "someresource1",
							DeviceIds:    []string{"1"},
						},
					},
				},
				{
					Name: "container2",
					Devices: []*podresourcesapi.ContainerDevices{
						{
							ResourceName: "someresource2",
							DeviceIds:    []string{"2"},
						},
					},
				},
			},
		},
	}
}

var _ = Describe("getHostname should return error if", func() {
	var _ = It("path with hostname file does not exists", func() {
		path := "someinvalidpath"
		hn, err := getHostname(path)
		Expect(hn).To(BeEmpty())
		Expect(err).ToNot(BeNil())
	})

	var _ = It("path exists but file is empty", func() {
		tempDir, err := os.MkdirTemp("", "adqhostnamefile")
		Expect(err).ToNot(HaveOccurred())
		path := filepath.Join(tempDir, "hostname")
		f, err := os.Create(path)
		Expect(err).ToNot(HaveOccurred())
		Expect(f).ToNot(BeNil())
		f.Close()
		hn, err := getHostname(path)
		Expect(hn).To(BeEmpty())
		Expect(err).ToNot(BeNil())
	})
})

var _ = Describe("GetKubeletClient should return error if", func() {
	var _ = It("is not able to get grpc client", func() {
		kubeletSocket = "https://invalidkubeletsocket.sock"
		kClient, err := GetKubeletClient(true, "", "", "")
		Expect(kClient).To(BeNil())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("protocol \"https\" not supported"))
	})

	var _ = It("is not able to get pod resources from client", func() {
		kubeletSocket = "somekubeletsocket.sock"
		kClient, err := GetKubeletClient(true, "", "", "")
		Expect(kClient).To(BeNil())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Error while dialing dial unix: missing address"))
	})

	var _ = It("is not able to get http client", func() {
		kClient, err := GetKubeletClient(true, "localhost", "10213", "/someinvalidCaPath")
		Expect(kClient).To(BeNil())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no such file or directory"))
	})
})

var _ = Describe("GetKubeletClient should return no error and non-nil client if", func() {
	var _ = It("is able to get http client", func() {
		kClient, err := GetKubeletClient(true, "localhost", "", path.Join(certTempDir, "ca.pem"))
		Expect(err).ToNot(HaveOccurred())
		Expect(kClient).ToNot(BeNil())
	})
})

var _ = Describe("GetPodResourceMap should", func() {
	var _ = Context("return error if", func() {
		var _ = It("can not find required resource", func() {
			rsMock.podResources = generatePodResources()

			kClient, err := GetKubeletClient(true, "localhost", "", path.Join(certTempDir, "ca.pem"))
			Expect(err).ToNot(HaveOccurred())

			_, err = kClient.GetPodResourceMap("testpod1", "default", "eno1")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("getPodResourceMap did not find net.intel.com/adq or net.intel.com/adq-shared resources in pod testpod1"))
		})
	})

	var _ = Context("not return an error and return valid ResourceInfo if", func() {
		var _ = It("can find matching net.intel.com/adq resource", func() {
			rsMock.podResources = generatePodResources()
			rsMock.podResources[0].Containers[0].Devices[0].ResourceName = AdqResourceName

			kClient, err := GetKubeletClient(true, "localhost", "", path.Join(certTempDir, "ca.pem"))
			Expect(err).ToNot(HaveOccurred())

			ri, err := kClient.GetPodResourceMap("testpod1", "default", "eno1")
			Expect(err).ToNot(HaveOccurred())

			Expect(ri).To(HaveLen(1))
			Expect(ri[0].ContainerName).To(Equal(rsMock.podResources[0].Containers[0].Name))
			Expect(ri[0].SingleQueueNumber).To(BeEmpty())
			Expect(ri[0].TC).To(Equal(rsMock.podResources[0].Containers[0].Devices[0].DeviceIds[0]))
		})
	})

	var _ = Context("not return an error and return valid ResourceInfo if", func() {
		var _ = It("can find matching net.intel.com/adq-shared resource", func() {
			rsMock.podResources = generatePodResources()
			rsMock.podResources[0].Containers[0].Devices[0].ResourceName = AdqSharedResourceName

			sharedTCNumber := uint8(5)
			adqm = &netlinktc.NetlinkTcMock{
				SharedTCNum: sharedTCNumber,
				SharedTCErr: nil,
			}
			adqtcInit = AdqTCInit

			kClient, err := GetKubeletClient(true, "localhost", "", path.Join(certTempDir, "ca.pem"))
			Expect(err).ToNot(HaveOccurred())

			ri, err := kClient.GetPodResourceMap("testpod1", "default", "eno1")
			Expect(err).ToNot(HaveOccurred())

			Expect(ri).To(HaveLen(1))
			Expect(ri[0].ContainerName).To(Equal(rsMock.podResources[0].Containers[0].Name))
			Expect(ri[0].SingleQueueNumber).To(Equal(rsMock.podResources[0].Containers[0].Devices[0].DeviceIds[0]))
			Expect(ri[0].TC).To(Equal(strconv.Itoa(int(sharedTCNumber))))
		})
	})
})

var _ = Describe("GetAdqConfig should return no error and valid AdqConfig if", func() {
	var _ = It("is able to get matching data from https kubelet /pods endpoint", func() {
		kClient, err := GetKubeletClient(true, "localhost", "10213", path.Join(certTempDir, "ca.pem"))
		Expect(err).ToNot(HaveOccurred())
		Expect(kClient).ToNot(BeNil())

		pod1 := v1.Pod{}
		pod1.Name = "testpod1"
		pod1.Namespace = "default"
		a := map[string]string{}
		a["someannotation"] = "somevalue"
		a[adqConfigAnnotation] = `[ { "name": "container1", "ports": { "local": ["12345/TCP"] } } ]`
		pod1.Annotations = a

		c1 := v1.Container{}
		c1.Name = "container1"
		c1.Ports = append(c1.Ports, v1.ContainerPort{
			ContainerPort: 12345,
			Protocol:      v1.ProtocolTCP,
		})
		pod1.Spec.Containers = append(pod1.Spec.Containers, c1)

		pl := v1.PodList{Items: []v1.Pod{pod1}}
		j, err := json.Marshal(&pl)
		Expect(err).ToNot(HaveOccurred())

		mux := http.NewServeMux()
		mux.HandleFunc("/pods", func(w http.ResponseWriter, req *http.Request) {
			_, _ = io.WriteString(w, string(j))
		})

		go func() {
			err = http.ListenAndServeTLS("localhost:10213", path.Join(certTempDir, "ca.pem"), path.Join(certTempDir, "key.pem"), mux)
			Expect(err).ToNot(HaveOccurred())
		}()

		// instead of sleep - performing fake checks to see if server is up and running before formal test
		Eventually(func() bool {
			_, err := kClient.GetAdqConfig("default", "testpod1")
			return err == nil
		}, "10s", "1s").Should(Equal(true))

		ace, err := kClient.GetAdqConfig("default", "testpod1")

		Expect(err).ToNot(HaveOccurred())
		Expect(ace).ToNot(BeNil())
		Expect(ace).To(HaveLen(1))
		Expect(ace[0].Name).To(Equal(c1.Name))
		Expect(ace[0].Ports.LocalPorts).To(HaveLen(1))
		Expect(ace[0].Ports.LocalPorts[0]).To(Equal(fmt.Sprintf("%d%s%s", c1.Ports[0].ContainerPort, adqConfigSepartor, c1.Ports[0].Protocol)))
	})
})

var _ = Describe("SyncPodResources should", func() {
	var _ = Context("not return error if", func() {
		var _ = It("no error case is invoked", func() {
			kClient, err := GetKubeletClient(true, "localhost", "", path.Join(certTempDir, "ca.pem"))
			Expect(err).ToNot(HaveOccurred())
			Expect(kClient).ToNot(BeNil())
			err = kClient.SyncPodResources()
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("return error if", func() {
		var _ = It("is not able to get grpc client", func() {
			kClient, err := GetKubeletClient(true, "localhost", "", path.Join(certTempDir, "ca.pem"))
			Expect(err).ToNot(HaveOccurred())
			Expect(kClient).ToNot(BeNil())
			kubeletSocket = "https://invalidkubeletsocket.sock"
			err = kClient.SyncPodResources()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("protocol \"https\" not supported"))
		})

	})

})

var _ = Describe("GetPodList should return error if", func() {
	var _ = It("response code from https server is not OK", func() {
		kClient, err := GetKubeletClient(true, "localhost", "10215", path.Join(certTempDir, "ca.pem"))
		Expect(err).ToNot(HaveOccurred())
		Expect(kClient).ToNot(BeNil())

		mux := http.NewServeMux()
		mux.HandleFunc("/pods", func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "this is some invalid string")
		})
		go func() {
			err = http.ListenAndServeTLS(":10215", path.Join(certTempDir, "ca.pem"), path.Join(certTempDir, "key.pem"), mux)
			Expect(err).ToNot(HaveOccurred())
		}()

		Eventually(func() bool {
			conn, err := net.Dial("tcp", ":10215")
			if err != nil {
				return false
			}
			conn.Close()
			return true
		}, "10s", "1s").Should(Equal(true))

		pl, err := kClient.GetPodList()
		Expect(pl).To(BeNil())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("HTTP resp status: %v", http.StatusNotFound)))
	})

	var _ = It("server send response that could not be decoded", func() {
		kClient, err := GetKubeletClient(true, "localhost", "10216", path.Join(certTempDir, "ca.pem"))
		Expect(err).ToNot(HaveOccurred())
		Expect(kClient).ToNot(BeNil())

		mux := http.NewServeMux()
		mux.HandleFunc("/pods", func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "this is some invalid string")
		})
		go func() {
			err = http.ListenAndServeTLS(":10216", path.Join(certTempDir, "ca.pem"), path.Join(certTempDir, "key.pem"), mux)
			Expect(err).ToNot(HaveOccurred())
		}()

		Eventually(func() bool {
			conn, err := net.Dial("tcp", ":10216")
			if err != nil {
				return false
			}
			conn.Close()
			return true
		}, "10s", "1s").Should(Equal(true))

		pl, err := kClient.GetPodList()
		Expect(pl).To(BeNil())
		Expect(err).To(HaveOccurred())
	})
})
