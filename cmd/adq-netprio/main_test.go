package main

import (
	"errors"
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containernetworking/cni/libcni"
	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/intel/adq-device-plugin/pkg/kubeletclient"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
)

func TestAdqNetprio(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ADQ netprio setting Test Suite")
}

const cniData = `
{
    "name": "chained",
    "cniVersion": "0.3.1",
    "plugins": [
        {
            "type": "cilium-cni",
            "enable-debug": false
        },
        {
            "type": "adq-cni"
        }
    ]
}
`

const cniDataInvalid = `
{
    "name": "chained",
    "cniVersion": "0.3.1",
    "plugins": [
        {
            "type": "cilium-cni",
            "enable-debug": false
        }
    ]
}
`

const cniConfigData = `
{
    "type": "adq-cni"
}
`

var (
	kClientMock     *kubeletclient.KubeletClientMock
	kClientGetError error

	//fsMock *fsNotifyMock
	tempCgroupFsDir string
)

func GetKubeletClientMock(httpClientEnabled bool, ksName, ksPort, caPath string) (kubeletclient.KubeletClient, error) {
	return kClientMock, kClientGetError
}

func createDirStructure() []string {
	fp := filepath.Join(tempCgroupFsDir, legacyCgroupPath)
	err := os.MkdirAll(fp, 0777)
	Expect(err).NotTo(HaveOccurred())
	l1 := [...]string{fp}
	l2 := [...]string{besteffortSlice, guaranteeSlice, burstableSlice}
	for _, p := range l2 {
		path := filepath.Join(fp, p)
		err = os.MkdirAll(path, 0777)
		Expect(err).ToNot(HaveOccurred())
	}
	d := getWatchDirs(l1[:], l2[:])

	return d
}

var _ = BeforeEach(func() {
	var err error
	tempCgroupFsDir, err = os.MkdirTemp("", "cgroupsfakedir")
	Expect(err).NotTo(HaveOccurred())
	getKubeletClient = GetKubeletClientMock
})

var _ = AfterEach(func() {
	err := os.RemoveAll(tempCgroupFsDir)
	Expect(err).NotTo(HaveOccurred())
})

var _ = Describe("getWatchDirs should return dirs to watch", func() {
	var _ = It("if path exist in file system", func() {
		d := createDirStructure()
		Expect(d).To(HaveLen(3))
	})
})

var _ = Describe("watchDirs should", func() {
	var _ = It("setup fsNotify.Watcher without error", func() {
		var err error
		podsWatcher, err = fsnotify.NewWatcher()
		Expect(err).ToNot(HaveOccurred())
		d := createDirStructure()
		Expect(d).To(HaveLen(3))
		err = watchDirs(d)
		Expect(err).ToNot(HaveOccurred())
		err = podsWatcher.Close()
		Expect(err).NotTo(HaveOccurred())
	})
})

var _ = Describe("addNetPrio should", func() {
	var _ = It("write netprio setting to file without error", func() {
		d := createDirStructure()
		Expect(d).To(HaveLen(3))
		id := uuid.New()

		pid := filepath.Join(d[1], id.String())
		err := os.Mkdir(pid, 0777)
		Expect(err).ToNot(HaveOccurred())

		path := filepath.Join(pid, ifPrioMapFile)
		err = addNetPrio("fakeiface", "5", path)
		Expect(err).ToNot(HaveOccurred())

		bs, err := os.ReadFile(path)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(bs)).To(ContainSubstring("fakeiface 5"))
	})

	var _ = It("return error if not possible to write setting", func() {
		err := addNetPrio("fakeiface", "5", "")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("loadConf should", func() {
	var validDefaultInterfaceNamePath string

	var _ = BeforeEach(func() {
		validDefaultInterfaceNamePath = defaultNodeConfigPath

		f, err := ioutil.TempFile("/tmp", "")
		Expect(err).NotTo(HaveOccurred())

		node_config := `
		{                                                                                                                                                                                                                                                                                                                                
			"EgressMode": "skbedit",                                                                                                                                                                                                                                                                                                     
			"FilterPrio": 1,                                                                                                                                                                                                                                                                                                             
			"Globals": {                                                                                                                                                                                                                                                                                                                 
				"Dev": "ens801f0"                                                                                                                                                                                                                                                                                                      
			}
		}
`
		err = os.WriteFile(f.Name(), []byte(node_config), 0644)
		Expect(err).NotTo(HaveOccurred())

		defaultNodeConfigPath = f.Name()

	})

	var _ = AfterEach(func() {
		defaultNodeConfigPath = validDefaultInterfaceNamePath
	})

	var _ = Context("return cniConf without error", func() {
		var _ = It("when correct configuration passed as parameter", func() {
			f, err := ioutil.TempFile("/tmp", "")
			Expect(err).NotTo(HaveOccurred())

			node_config := `
			{                                                                                                                                                                                                                                                                                                                                
			    "EgressMode": "skbedit",                                                                                                                                                                                                                                                                                                     
			    "FilterPrio": 1,                                                                                                                                                                                                                                                                                                             
			    "Globals": {                                                                                                                                                                                                                                                                                                                 
				"Dev": "ens801f0"                                                                                                                                                                                                                                                                                                      
			    }
			}
			`
			err = os.WriteFile(f.Name(), []byte(node_config), 0644)
			Expect(err).NotTo(HaveOccurred())

			defaultNodeConfigPath = f.Name()

			b := []byte(cniConfigData)
			c, err := loadConf(b)
			Expect(err).NotTo(HaveOccurred())
			Expect(c).NotTo(BeNil())
			Expect(c.Master).To(ContainSubstring("ens801f0"))
		})
	})
	var _ = Context("return error", func() {
		var _ = It("when config is corrupted", func() {
			b := []byte("corrupted config")
			c, err := loadConf(b)
			Expect(err).To(HaveOccurred())
			Expect(c).To(BeNil())
		})

		var _ = It("when config does not contains master element and it's not able to read node config file", func() {
			defaultNodeConfigPath = "./invalidNodeConfigPath"
			b := []byte(cniConfigData)
			c, err := loadConf(b)
			Expect(err).To(HaveOccurred())
			Expect(c).To(BeNil())
		})
	})
})

var _ = Describe("getRunningContainers should", func() {
	var _ = It("return 1 running container for given input", func() {
		pod := kubeletclient.GenerateFakePod()
		m, r := getRunningContainers(pod)
		Expect(r).To(BeTrue())
		Expect(m).To(HaveLen(1))
	})
})

var _ = Describe("getPod should", func() {
	var _ = It("return pod for valid uuid", func() {
		podList := &v1.PodList{}
		pod := kubeletclient.GenerateFakePod()
		podList.Items = append(podList.Items, *pod)
		r := getPod(podList, "d801b01b-666c-4973-8e19-590e7cf8a273")
		Expect(r).ToNot(BeNil())
	})

	var _ = It("return nil for invalid uuid", func() {
		podList := &v1.PodList{}
		pod := kubeletclient.GenerateFakePod()
		podList.Items = append(podList.Items, *pod)
		r := getPod(podList, "invalid")
		Expect(r).To(BeNil())
	})
})

var _ = Describe("watchPodList should", func() {
	var validDefaultInterfaceNamePath string

	var _ = BeforeEach(func() {
		validDefaultInterfaceNamePath = defaultNodeConfigPath

		f, err := ioutil.TempFile("/tmp", "")
		Expect(err).NotTo(HaveOccurred())

		node_config := `
		{                                                                                                                                                                                                                                                                                                                                
		    "EgressMode": "skbedit",                                                                                                                                                                                                                                                                                                     
		    "FilterPrio": 1,                                                                                                                                                                                                                                                                                                             
		    "Globals": {                                                                                                                                                                                                                                                                                                                 
			"Dev": "ens801f0"                                                                                                                                                                                                                                                                                                      
		    }
		}
		`
		err = os.WriteFile(f.Name(), []byte(node_config), 0644)
		Expect(err).NotTo(HaveOccurred())

		defaultNodeConfigPath = f.Name()

	})

	var _ = AfterEach(func() {
		defaultNodeConfigPath = validDefaultInterfaceNamePath
	})

	var _ = It("update netprio for pod", func() {
		b := []byte(cniConfigData)
		c, err := loadConf(b)
		Expect(err).NotTo(HaveOccurred())
		Expect(c).NotTo(BeNil())
		duration, err := time.ParseDuration("200ms")
		Expect(err).NotTo(HaveOccurred())
		Expect(duration).NotTo(BeNil())
		d := createDirStructure()
		Expect(d).To(HaveLen(3))
		kClientMock = &kubeletclient.KubeletClientMock{}
		kClientMock.ResourceMap = []*kubeletclient.ResourceInfo{
			{
				TC:            "5",
				ContainerName: "redis",
			},
		}
		done := make(chan bool)
		// wait until routine is started
		go func() {
			_ = watchPodList(c, &duration, "silpixa00401197c", d, done)
		}()

		time.Sleep(duration)
		// fake pod create
		podDir := filepath.Join(d[0], "podd801b01b_666c_4973_8e19_590e7cf8a273.slice")
		err = os.MkdirAll(podDir, 0777)
		Expect(err).ToNot(HaveOccurred())
		time.Sleep(duration)
		// fake pause container create
		pcDir := filepath.Join(podDir, "cri-containerd-pause63fd6500ac65ad4b168f25407b8a65199ac5ec54d389b84f159051566d4")
		err = os.MkdirAll(pcDir, 0777)
		Expect(err).ToNot(HaveOccurred())
		time.Sleep(duration)
		// fake container create
		cDir := filepath.Join(podDir, "cri-containerd-d541163fd6500ac65ad4b168f25407b8a65199ac5ec54d389b84f159051566d4")
		err = os.MkdirAll(cDir, 0777)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() bool {
			f := filepath.Join(cDir, ifPrioMapFile)
			bs, err := os.ReadFile(f)
			if err != nil {
				//file not created yet
				return false
			}
			s := c.Master + " 5"
			Expect(string(bs)).To(ContainSubstring(s))
			return true
		}, "20s", "1s").Should(Equal(true))
		done <- true
	})

	var _ = It("remove container watch if pod dir is removed", func() {
		b := []byte(cniConfigData)
		c, err := loadConf(b)
		Expect(err).NotTo(HaveOccurred())
		Expect(c).NotTo(BeNil())
		duration, err := time.ParseDuration("500ms")
		Expect(err).NotTo(HaveOccurred())
		Expect(duration).NotTo(BeNil())
		d := createDirStructure()
		Expect(d).To(HaveLen(3))
		kClientMock = &kubeletclient.KubeletClientMock{}
		kClientMock.ResourceMap = []*kubeletclient.ResourceInfo{
			{
				TC:            "5",
				ContainerName: "redis",
			},
		}
		done := make(chan bool)
		// wait until routine is started
		go func() {
			_ = watchPodList(c, &duration, "silpixa00401197c", d, done)
		}()
		time.Sleep(duration)
		// fake pod create
		podDir := filepath.Join(d[0], "podd801b01b_666c_4973_8e19_590e7cf8a273.slice")
		err = os.MkdirAll(podDir, 0777)
		Expect(err).ToNot(HaveOccurred())
		time.Sleep(duration)
		// checking if there we not be a segfault
		err = os.RemoveAll(podDir)
		Expect(err).ToNot(HaveOccurred())

		done <- true
	})
})

var _ = Describe("getCniConf should", func() {
	var validDefaultInterfaceNamePath string

	var _ = BeforeEach(func() {
		validDefaultInterfaceNamePath = defaultNodeConfigPath

		f, err := ioutil.TempFile("/tmp", "")
		Expect(err).NotTo(HaveOccurred())

		node_config := `{                                                                                                                                                                                                                                                                                                                                
			"EgressMode": "skbedit",                                                                                                                                                                                                                                                                                                     
			"FilterPrio": 1,                                                                                                                                                                                                                                                                                                             
			"Globals": {                                                                                                                                                                                                                                                                                                                 
				"Dev": "ens801f0"                                                                                                                                                                                                                                                                                                      
			}
		}
		`
		err = os.WriteFile(f.Name(), []byte(node_config), 0644)
		Expect(err).NotTo(HaveOccurred())

		defaultNodeConfigPath = f.Name()

	})

	var _ = AfterEach(func() {
		defaultNodeConfigPath = validDefaultInterfaceNamePath
	})

	var _ = It("return correct cniConf for valid input", func() {
		b := []byte(cniData)
		ncl, err := libcni.ConfListFromBytes(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(ncl).ToNot(BeNil())
		c, err := getCniConf(ncl)
		Expect(err).ToNot(HaveOccurred())
		Expect(c.Master).ToNot(BeEmpty())
	})

	var _ = It("return error when CNI config does not have ADQ configuration", func() {
		b := []byte(cniDataInvalid)
		ncl, err := libcni.ConfListFromBytes(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(ncl).ToNot(BeNil())
		c, err := getCniConf(ncl)
		Expect(err).To(HaveOccurred())
		Expect(c).To(BeNil())
	})
})

var _ = Describe("getCniConfig shoud", func() {
	var validDefaultInterfaceNamePath string

	var _ = BeforeEach(func() {
		validDefaultInterfaceNamePath = defaultNodeConfigPath

		f, err := ioutil.TempFile("/tmp", "")
		Expect(err).NotTo(HaveOccurred())

		node_config := `{                                                                                                                                                                                                                                                                                                                                
			"EgressMode": "skbedit",                                                                                                                                                                                                                                                                                                     
			"FilterPrio": 1,                                                                                                                                                                                                                                                                                                             
			"Globals": {                                                                                                                                                                                                                                                                                                                 
				"Dev": "ens801f0"                                                                                                                                                                                                                                                                                                      
			}
		}
		`
		err = os.WriteFile(f.Name(), []byte(node_config), 0644)
		Expect(err).NotTo(HaveOccurred())

		defaultNodeConfigPath = f.Name()

	})

	var _ = AfterEach(func() {
		defaultNodeConfigPath = validDefaultInterfaceNamePath
	})

	var _ = It("return error if path to config is invalid", func() {
		c, err := getCniConfig("invalidfilepath")
		Expect(err).To(HaveOccurred())
		Expect(c).To(BeNil())
	})

	var _ = It("return valid cniConf for valid CNI config", func() {
		p := filepath.Join(tempCgroupFsDir, "cni.conflist")
		b := []byte(cniData)
		err := os.WriteFile(p, b, 0777)
		Expect(err).ToNot(HaveOccurred())
		c, err := getCniConfig(p)
		Expect(err).ToNot(HaveOccurred())
		Expect(c).ToNot(BeNil())
	})
})

var _ = Describe("getNodeName should", func() {
	var _ = It("return error if node name is not set", func() {
		nodeName, err := getNodeName()
		Expect(err).To(HaveOccurred())
		Expect(nodeName).To(BeEmpty())
	})

	var _ = It("return node name if set", func() {
		expectedNodeName := "test_node"
		err := os.Setenv("NODE_NAME", expectedNodeName)
		Expect(err).ToNot(HaveOccurred())
		nodeName, err := getNodeName()
		Expect(err).ToNot(HaveOccurred())
		Expect(nodeName).ToNot(BeEmpty())
		Expect(nodeName).To(Equal(expectedNodeName))
	})
})

var _ = Describe("updatePath should", func() {
	var _ = Context("exit when kubeclient return error", func() {
		var _ = It("on fetching pod list", func() {
			d := createDirStructure()
			Expect(d).To(HaveLen(3))
			kClientMock = &kubeletclient.KubeletClientMock{}
			kClientMock.GetPodListErr = errors.New("get pod list error")
			duration, err := time.ParseDuration("100ms")
			Expect(err).ToNot(HaveOccurred())
			podDir := filepath.Join(d[0], "podd801b01b_666c_4973_8e19_590e7cf8a273.slice")
			err = os.MkdirAll(podDir, 0777)
			Expect(err).ToNot(HaveOccurred())
			// fake container create
			cDir := filepath.Join(podDir, "cri-containerd-d541163fd6500ac65ad4b168f25407b8a65199ac5ec54d389b84f159051566d4")
			err = os.MkdirAll(cDir, 0777)
			Expect(err).ToNot(HaveOccurred())
			h := newPathUpdater(kClientMock, &duration, "nodeName", "testIface")
			upi := &updatePathInfo{podUID: "d801b01b-666c-4973-8e19-590e7cf8a273", podName: "redis", podNamespace: "default", containerPath: cDir}
			h.addPath(*upi)
			path := filepath.Join(cDir, ifPrioMapFile)
			time.Sleep(duration)
			Eventually(func() bool {
				// check if netprio file is not created
				_, err := os.Stat(path)
				return err != nil
			}, "2s", "500ms").Should(Equal(true))
			h.ticker.Stop()
		})

		var _ = It("on pod resource sync", func() {
			d := createDirStructure()
			Expect(d).To(HaveLen(3))
			kClientMock = &kubeletclient.KubeletClientMock{}
			kClientMock.SyncPodResourcesErr = errors.New("sync pod resource error")
			duration, err := time.ParseDuration("100ms")
			Expect(err).ToNot(HaveOccurred())
			podDir := filepath.Join(d[0], "podd801b01b_666c_4973_8e19_590e7cf8a273.slice")
			err = os.MkdirAll(podDir, 0777)
			Expect(err).ToNot(HaveOccurred())
			// fake container create
			cDir := filepath.Join(podDir, "cri-containerd-d541163fd6500ac65ad4b168f25407b8a65199ac5ec54d389b84f159051566d4")
			err = os.MkdirAll(cDir, 0777)
			Expect(err).ToNot(HaveOccurred())
			h := newPathUpdater(kClientMock, &duration, "nodeName", "testIface")
			upi := &updatePathInfo{podUID: "d801b01b-666c-4973-8e19-590e7cf8a273", podName: "redis", podNamespace: "default", containerPath: cDir}
			h.addPath(*upi)
			path := filepath.Join(cDir, ifPrioMapFile)
			time.Sleep(duration)
			Eventually(func() bool {
				// check if netprio file is not created
				_, err := os.Stat(path)
				return err != nil
			}, "2s", "500ms").Should(Equal(true))
			h.ticker.Stop()
		})
	})
	var _ = Context("handles updates when", func() {
		var _ = It("Pod with uuid does not exist", func() {
			d := createDirStructure()
			Expect(d).To(HaveLen(3))
			kClientMock = &kubeletclient.KubeletClientMock{}
			kClientMock.SyncPodResourcesErr = errors.New("sync pod resource error")
			duration, err := time.ParseDuration("100ms")
			Expect(err).ToNot(HaveOccurred())
			podDir := filepath.Join(d[0], "podd801b01b_666c_4973_8e19_590e7cf8a273.slice")
			err = os.MkdirAll(podDir, 0777)
			Expect(err).ToNot(HaveOccurred())
			cDir := filepath.Join(podDir, "cri-containerd-d541163fd6500ac65ad4b168f25407b8a65199ac5ec54d389b84f159051566d4")
			err = os.MkdirAll(cDir, 0777)
			Expect(err).ToNot(HaveOccurred())
			kClientMock = &kubeletclient.KubeletClientMock{}
			kClientMock.ResourceMap = []*kubeletclient.ResourceInfo{
				{
					TC:            "5",
					ContainerName: "redis",
				},
			}

			h := newPathUpdater(kClientMock, &duration, "nodeName", "testIface")
			upi := &updatePathInfo{podUID: "a801b01b-666c-4973-8e19-590e7cf8a273", podName: "redis", podNamespace: "default", containerPath: cDir}
			h.addPath(*upi)

			time.Sleep(duration)
			Eventually(func() bool {
				return len(h.paths) == 0
			}, "2s", "500ms").Should(BeTrue())
			h.ticker.Stop()
		})

		var _ = It("Pod does not container ADQ info", func() {
			d := createDirStructure()
			Expect(d).To(HaveLen(3))
			kClientMock = &kubeletclient.KubeletClientMock{}
			kClientMock.SyncPodResourcesErr = errors.New("sync pod resource error")
			duration, err := time.ParseDuration("100ms")
			Expect(err).ToNot(HaveOccurred())
			podDir := filepath.Join(d[0], "podd801b01b_666c_4973_8e19_590e7cf8a273.slice")
			err = os.MkdirAll(podDir, 0777)
			Expect(err).ToNot(HaveOccurred())
			cDir := filepath.Join(podDir, "cri-containerd-d541163fd6500ac65ad4b168f25407b8a65199ac5ec54d389b84f159051566d4")
			err = os.MkdirAll(cDir, 0777)
			Expect(err).ToNot(HaveOccurred())
			kClientMock = &kubeletclient.KubeletClientMock{}
			kClientMock.GetResourceMapErr = errors.New("get pod resource map error")
			h := newPathUpdater(kClientMock, &duration, "nodeName", "testIface")
			upi := &updatePathInfo{podUID: "d801b01b-666c-4973-8e19-590e7cf8a273", podName: "redis", podNamespace: "default", containerPath: cDir}
			h.addPath(*upi)

			time.Sleep(duration)
			Eventually(func() bool {
				return len(h.paths) == 0
			}, "2s", "500ms").Should(BeTrue())
			h.ticker.Stop()
		})
	})
})

var _ = Describe("paseFlags() should", func() {
	var _ = Context("return valid reconcile period and CNI config path", func() {
		var _ = It("for valid input arguments", func() {
			td, err := time.ParseDuration("3s")
			path := "/some/path"
			Expect(err).ToNot(HaveOccurred())
			d, p, _, err := parseFlags("test", []string{"-reconcile-period", "3s", "-cni-config-path", path})
			Expect(err).ToNot(HaveOccurred())
			Expect(d).To(Equal(td))
			Expect(p).To(Equal(path))
		})
	})

	var _ = Context("return error", func() {
		var _ = It("when path to CNI config not set", func() {
			_, _, _, err := parseFlags("test", []string{"-reconcile-period", "3s"})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("config path for CNI not set"))
		})

		var _ = It("when -h is passed as input parameter", func() {
			_, _, out, err := parseFlags("test", []string{"-h"})
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(flag.ErrHelp))
			Expect(out).ToNot(BeEmpty())
		})
	})
})
