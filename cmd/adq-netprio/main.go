// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/containernetworking/cni/libcni"
	"github.com/fsnotify/fsnotify"
	"github.com/intel/adq-device-plugin/pkg/kubeletclient"
	"github.com/intel/adq-device-plugin/pkg/nodeconfigtypes"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

var (
	getKubeletClient   = kubeletclient.GetKubeletClient
	getFsNotifyWatcher = fsnotify.NewWatcher

	// This is overridden in the linker script
	BuildVersion          = "version unknown"
	podsWatcher           *fsnotify.Watcher
	defaultNodeConfigPath = "/etc/cni/net.d/adq-cni.d/node-config"
	egressMode            = "skbedit"
)

const (
	legacyCgroupPath = "/sys/fs/cgroup/net_prio/"
	hybridCgroupPath = "/sys/fs/cgroup/unified/net_prio/"
	dockerPrefix     = "docker://"
	crioPrefix       = "cri-o://"
	containerdPrefix = "containerd://"
	ifPrioMapFile    = "net_prio.ifpriomap"
	adqCniName       = "adq-cni"
	besteffortSlice  = "kubepods.slice/kubepods-besteffort.slice/"
	burstableSlice   = "kubepods.slice/kubepods-burstable.slice/"
	guaranteeSlice   = "kubepods.slice/"
)

type cniConf struct {
	Master string `json:"-"`

	KubeletServerName string `json:"kubeletServerName,omitempty"`
	KubeletPort       string `json:"kubeletPort,omitempty"`
	KubeletCAPath     string `json:"kubeletCAPath,omitempty"`
}

type podInfo struct {
	podUID         string
	podNamespace   string
	podName        string
	containersPath []string
	containersNum  int
}

type updatePathInfo struct {
	podUID        string
	podName       string
	podNamespace  string
	containerPath string
}

type containerInfo struct {
	cid string
	tc  string
}

type pathUpdater struct {
	ticker   *time.Ticker
	add      chan updatePathInfo
	paths    []updatePathInfo
	nodeName string
	kc       kubeletclient.KubeletClient
	master   string
}

func newPathUpdater(kc kubeletclient.KubeletClient, reconcilePeriod *time.Duration, node, master string) *pathUpdater {
	ret := &pathUpdater{
		ticker:   time.NewTicker(*reconcilePeriod),
		add:      make(chan updatePathInfo),
		nodeName: node,
		kc:       kc,
		master:   master,
	}
	go ret.run()
	return ret
}

func (h *pathUpdater) run() {
	for {
		select {
		case <-h.ticker.C:
			//update path
			if len(h.paths) == 0 {
				break
			}
			h.updatePath()

		case u := <-h.add:
			h.paths = append(h.paths, u)
		}
	}
}

func (h *pathUpdater) addPath(path updatePathInfo) {
	h.add <- path
}

func (h *pathUpdater) updatePath() {
	var logger = log.WithField("func", "updatePath")
	logger.Debugf("UpdatePath len(paths)=%v", len(h.paths))

	pods, err := h.kc.GetPodList()
	if err != nil {
		logger.Errorf("%v", err)
		return
	}
	if err := h.kc.SyncPodResources(); err != nil {
		log.Error(err)
		return
	}

	for i := len(h.paths) - 1; i >= 0; i-- {
		pod := getPod(pods, h.paths[i].podUID)
		if pod == nil {
			//remove from list
			h.paths = append(h.paths[:i], h.paths[i+1:]...)
			continue
		}
		containers, ok := getRunningContainers(pod)
		if !ok {
			logger.Infof("Not all containers are running in pod: %s skipping...", h.paths[i].podName)
			// wait for all container runngin or update one by one ?
			continue
		}

		res, err := h.kc.GetPodResourceMap(h.paths[i].podName, h.paths[i].podNamespace, h.master)
		if err != nil {
			logger.Infof("did not find ADQ resource - removing %+v", h.paths[i])
			h.paths = append(h.paths[:i], h.paths[i+1:]...)
			continue
		}

		ci := getContainerInfo(res, containers, h.paths[i].containerPath)
		if ci == nil {
			// remove from list
			logger.Infof("Did not find CID with ADQ on list - removing: %+v", h.paths[i])
			h.paths = append(h.paths[:i], h.paths[i+1:]...)
			continue
		}

		logger.Infof("Will attemp to update pod %s uid %s container path %s container info %v", h.paths[i].podName, h.paths[i].podUID, h.paths[i].containerPath, ci)

		path := h.paths[i].containerPath
		path = filepath.Join(path, ifPrioMapFile)
		if err := addNetPrio(h.master, ci.tc, path); err != nil {
			logger.Errorf("could not update %s err %v", ifPrioMapFile, err)
		}
		h.paths = append(h.paths[:i], h.paths[i+1:]...)
	}
}

func getRunningContainers(pod *v1.Pod) (map[string]string, bool) {
	var logger = log.WithField("func", "getRunningContainers")
	cnts := make(map[string]string)

	// check if each container already has its status
	if len(pod.Status.InitContainerStatuses)+len(pod.Status.ContainerStatuses) != len(pod.Spec.InitContainers)+len(pod.Spec.Containers) {
		logger.Infof("Container count in pod status does not match the spec - init contaner status: %v container status: %v",
			pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses)
		return cnts, false
	}

	for _, status := range pod.Status.ContainerStatuses {
		logger.Infof("container %s(%v), state %v", status.Name, status.Ready, status.State)
		if !status.Ready {
			return cnts, false
		}
		cid := status.ContainerID
		for _, prefix := range [...]string{dockerPrefix, crioPrefix, containerdPrefix} {
			cid = strings.TrimPrefix(cid, prefix)
		}
		cnts[status.Name] = cid
	}

	if len(cnts) == 0 {
		return cnts, false
	}

	return cnts, true
}

func loadConf(bytes []byte) (*cniConf, error) {
	var logger = log.WithField("func", "loadConf")
	logger.Debugf("bytes %s", bytes)
	n := &cniConf{}

	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("loading network configuration unsuccessful: %v", err)
	}

	nodeConfig, err := os.ReadFile(defaultNodeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("Unable to read node config from %v, err: %v", defaultNodeConfigPath, err)
	}

	var nc nodeconfigtypes.AdqNodeConfig
	err = json.Unmarshal(nodeConfig, &nc)
	if err != nil {
		return nil, fmt.Errorf("Error when unmarshalling node-config: %v", err)
	}

	n.Master = nc.Globals.Dev
	egressMode = nc.EgressMode

	return n, nil
}

func addNetPrio(iface, tc, path string) error {
	var logger = log.WithField("func", "addNetPrio")
	prioStr := iface + " " + tc
	err := os.WriteFile(path, []byte(prioStr), 0644)
	if err != nil {
		logger.Errorf("Failed to update network priority path %s, err %v", path, err)
		return err
	}
	logger.Infof("Updated network priority for path %s, tc %s, iface %s", path, tc, iface)
	return nil
}

func getWatchDirs(dir []string, sub []string) []string {
	rv := make([]string, 0)
	for _, p := range dir {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			for _, d := range sub {
				path := filepath.Join(p, d)
				rv = append(rv, path)
			}
		}
	}
	return rv
}

func watchDirs(d []string) error {
	var logger = log.WithField("func", "watchDirs")
	for _, c := range d {
		logger.Infof("add watch on path %s", c)
		if err := podsWatcher.Add(c); err != nil {
			return err
		}
	}
	return nil
}

func getUIDFromPath(path string) string {
	var re = regexp.MustCompile(`(?m)[0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12}`)
	m := re.FindString(path)
	if len(m) > 0 {
		m = strings.ReplaceAll(m, "_", "-")
	}
	return m
}

func getPod(pods *v1.PodList, uid string) *v1.Pod {
	for _, p := range pods.Items {
		if string(p.GetUID()) == uid {
			return &p
		}
	}
	return nil
}

func getContainerInfo(res []*kubeletclient.ResourceInfo, containers map[string]string, cPath string) *containerInfo {
	for _, r := range res {
		if uid, ok := containers[r.ContainerName]; ok {
			if strings.Contains(cPath, uid) {
				return &containerInfo{cid: uid, tc: r.TC}
			}
		}
	}
	return nil
}

func getAdqContainersCount(containers []v1.Container) int {
	var logger = log.WithField("func", "getAdqContainersCount")
	rv := 0
	for _, cnt := range containers {
		for n, q := range cnt.Resources.Limits {
			logger.Infof("Container %s Limits: %s=%s", cnt.Name, n.String(), q.String())
			if kubeletclient.AdqResourceName == n.String() || kubeletclient.AdqSharedResourceName == n.String() {
				rv++
			}
		}

	}
	return rv
}

func watchPodList(c *cniConf, reconcilePeriod *time.Duration, nodeName string, dirs []string, done <-chan bool) error {
	var logger = log.WithField("func", "watchPodList")
	kc, err := getKubeletClient(true, c.KubeletServerName, c.KubeletPort, c.KubeletCAPath)
	if err != nil {
		return fmt.Errorf("failed to get a KubeletClient instance: %v", err)
	}

	podsWatcher, err = getFsNotifyWatcher()
	if err != nil {
		return fmt.Errorf("cannot init watcher %v", err)
	}
	defer podsWatcher.Close()
	containtersWatcher, err := getFsNotifyWatcher()
	if err != nil {
		return fmt.Errorf("cannot init watcher %v", err)
	}
	defer containtersWatcher.Close()
	visit := make(map[string]podInfo)
	pathUpdaterObj := newPathUpdater(kc, reconcilePeriod, nodeName, c.Master)

	go func() {
		for {
			select {
			case event, ok := <-podsWatcher.Events:
				if !ok {
					logger.Errorf("fetching inotify events failed")
					return
				}
				if event.Op&fsnotify.Create == fsnotify.Create {
					logger.Infof("Pod event: %v", event)
					uid := getUIDFromPath(event.Name)
					if len(uid) == 0 {
						logger.Errorf("could not find Pod uid in path %s", event.Name)
						break
					}
					pods, err := kc.GetPodList()
					if err != nil {
						logger.Errorf("failed to get pod list: %v", err)
						break
					}
					p := getPod(pods, uid)
					if p == nil {
						break
					}

					cnts := getAdqContainersCount(p.Spec.Containers)
					if cnts > 0 {
						visit[event.Name] = podInfo{podName: p.GetName(), podNamespace: p.Namespace, podUID: string(p.GetUID()),
							containersNum: len(p.Spec.Containers) + len(p.Spec.InitContainers)}
						err := containtersWatcher.Add(event.Name)
						if err != nil {
							logger.Errorf("Failed to create container watcher: %v", err)
							break
						}
					}
				}
				if event.Op&fsnotify.Remove == fsnotify.Remove {
					logger.Infof("Pod remove event: %v", event)
					if _, ok := visit[event.Name]; ok {
						logger.Infof("remove containers watcher")
						delete(visit, event.Name)
					}
				}
			case err, ok := <-podsWatcher.Errors:
				if !ok {
					return
				}
				logger.WithError(err).Error("inotify error occured")
			case event, ok := <-containtersWatcher.Events:
				if !ok {
					logger.Errorf("fetching inotify events failed: %v", ok)
					return
				}
				if event.Op&fsnotify.Create == fsnotify.Create {
					logger.Infof("Container event: %v", event)
					key := filepath.Dir(event.Name)
					watch, ok := visit[key]
					if !ok {
						logger.Infof("event %s not found", event.Name)
						break
					}
					watch.containersPath = append(watch.containersPath, event.Name)

					visit[key] = watch

					pathUpdaterObj.addPath(updatePathInfo{podUID: watch.podUID, podName: watch.podName, podNamespace: watch.podNamespace, containerPath: event.Name})
					// if event was triggered (container number) + 1 (pause container) times remove a watch
					if len(watch.containersPath) >= watch.containersNum+1 {
						logger.Infof("We receive update from all containers remove a watch")
						err := containtersWatcher.Remove(key)
						if err != nil {
							logger.Errorf("Failed to delete container watcher: %v", err)
							break
						}
						delete(visit, key)
					}
				}
			}
		}
	}()
	err = watchDirs(dirs)
	if err != nil {
		return err
	}
	<-done
	podsWatcher.Close()
	containtersWatcher.Close()
	return nil
}

func getCniConf(cniConfList *libcni.NetworkConfigList) (cniConf *cniConf, err error) {
	var logger = log.WithField("func", "getCniConf")
	for _, p := range cniConfList.Plugins {
		if p.Network.Type == adqCniName {
			cniConf, err = loadConf(p.Bytes)
			if err != nil {
				logger.WithError(err).Error("Cannot get CNI config")
				return nil, err
			}
		}
	}
	if cniConf == nil {
		return nil, errors.New("cannot find ADQ configuration in CNI config")
	}
	return cniConf, nil
}

func getCniConfig(path string) (*cniConf, error) {
	var logger = log.WithField("func", "getConfig")
	cniConfList, err := libcni.ConfListFromFile(path)
	if err != nil {
		logger.WithError(err).Error("Cannot get CNI config")
		return nil, err
	}
	return getCniConf(cniConfList)
}

func getNodeName() (string, error) {
	var logger = log.WithField("func", "getNodeName")
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		logger.Error("unable to get K8s node name from ENV var NODE_NAME")
		return "", errors.New("cannot get node name from evironment")
	}
	return nodeName, nil
}

func parseFlags(name string, args []string) (reconcilePeriod time.Duration, cniConfigPath, out string, err error) {
	logger := log.WithField("func", "parseFlags")
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	var buf bytes.Buffer

	flags.SetOutput(&buf)

	defaultReconcile, err := time.ParseDuration("2s")
	if err != nil {
		logger.Error("Failed to parse default value for reconcile-period parameter")
		return 0, "", buf.String(), err
	}

	flags.DurationVar(&reconcilePeriod, "reconcile-period", defaultReconcile, "reconcile period for Pod scan")
	flags.StringVar(&cniConfigPath, "cni-config-path", "", "Path to CNI config file")

	err = flags.Parse(args)
	if err != nil {
		return 0, "", buf.String(), err
	}

	if len(cniConfigPath) == 0 {
		logger.Error("config path for CNI not set")
		return 0, "", buf.String(), fmt.Errorf("config path for CNI not set")
	}

	return reconcilePeriod, cniConfigPath, buf.String(), nil
}

func main() {
	var logger = log.WithField("func", "main")

	reconcilePeriod, cniConfigPath, out, err := parseFlags(os.Args[0], os.Args[1:])
	if err == flag.ErrHelp {
		log.Infoln(out)
		os.Exit(2)
	} else if err != nil {
		log.Error(out)
		os.Exit(1)
	}

	nodeName, err := getNodeName()
	if err != nil {
		os.Exit(1)
	}

	cniConf, err := getCniConfig(cniConfigPath)
	if err != nil {
		os.Exit(1)
	}

	if egressMode == "skbedit" {
		logger.Infof("Egress mode is set to skbedit")
		done := make(chan os.Signal, 1)
		signal.Notify(done, syscall.SIGTERM, syscall.SIGINT)
		<-done
		os.Exit(0)
	}

	logger.Infof("Running ADQ cgroup netprio daemon: version %s CNI config path %s", cniConfigPath, BuildVersion)

	logger.Infof("CNI config %v", cniConf)
	pdirs := [...]string{legacyCgroupPath, hybridCgroupPath}
	subdirs := [...]string{burstableSlice, besteffortSlice, guaranteeSlice}
	dirs := getWatchDirs(pdirs[:], subdirs[:])
	done := make(chan bool)
	if err := watchPodList(cniConf, &reconcilePeriod, nodeName, dirs, done); err != nil {
		done <- true
		logger.Error(err)
		os.Exit(1)
	}
}
