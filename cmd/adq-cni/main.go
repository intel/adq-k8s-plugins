// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation

package main

import (
	"io"
	"os"
	"path"
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/intel/adq-device-plugin/pkg/plugin"
	log "github.com/sirupsen/logrus"
)

const (
	logDir = "/var/log"
)

func init() {
	logInit()
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func logInit() {
	logFilename := path.Join(logDir, "adq-cni.log")
	logFile, err := os.OpenFile(logFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("adq-cni log file error: %v", err)
	}
	logs := io.MultiWriter(logFile)
	log.SetOutput(logs)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		PadLevelText:     true,
		QuoteEmptyFields: true,
	})
}

func main() {
	skel.PluginMain(plugin.CmdAdd, plugin.CmdCheck, plugin.CmdDel, version.All, buildversion.BuildString("adq"))
}
