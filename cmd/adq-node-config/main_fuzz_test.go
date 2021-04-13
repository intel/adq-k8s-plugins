package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/intel/adq-device-plugin/pkg/nodeconfigtypes"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func FuzzGetNodeConfig(f *testing.F) {
	seed := `
    {
      "NodeConfigs": [
        {
        	"Labels": {
        	    "kubernetes.io/os": "linux"
        	},
          	"EgressMode": "skbedit",
          	"FilterPrio": 1,
        	"Globals": {
			"Arpfilter": false,
			"Bpstop": false,
			"BpstopCfg": false,
			"Dev": "ens123",
			"Txring": 100,
			"Rxring": 100,
        		"Queues": 16,
            		"Busypoll": 50000,
            		"Busyread": 50000,
            		"Txadapt": false,
            		"Txusecs": 500,
            		"Rxadapt": false,
            		"Rxusecs": 500,
            		"Optimize": false,
            		"Cpus": "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
            		"Numa": "0"
        },
          	"TrafficClass": [
            		{
              			"Queues": 4,
				"Pollers": 4,
				"PollerTimeout": 1000,
				"Cpus": "auto",
            			"Numa": "local"
            		},
            		{
              			"Queues": 4,
				"Pollers": 4,
				"PollerTimeout": 1000,
				"Cpus": "16,17,18,19",
            			"Numa": "remote"
            		},
            		{
              			"Queues": 4,
				"Pollers": 4,
				"PollerTimeout": 1000,
				"Cpus": "16,17,18,19",
            			"Numa": "all"
            		},
            		{
              			"Queues": 4,
				"Pollers": 4,
				"PollerTimeout": 1000,
            		},
            		{
              			"Queues": 32,
              			"Mode": "shared"
            		}
          	]
        }
      ]
    }
	`
	f.Add([]byte(seed))

	masterInterface := "ethx"

	f.Fuzz(func(t *testing.T, fcfg []byte) {
		node := &v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"labelA": "A",
				},
			},
		}

		// pass fuzzed config by replacing get() function
		getClusterConfig = func(path string) ([]byte, error) {
			return fcfg, nil
		}

		adqsetupConfig, nodeConfig, err := getNodeConfig(node, masterInterface, "foo")

		if err != nil { // getNodeConfig can ONLY return below errors with empty result
			if strings.Contains(err.Error(), "Json Unmarshall error") && adqsetupConfig == "" && nodeConfig == "" {
				return
			} else if strings.Contains(err.Error(), "Node config is empty") && adqsetupConfig == "" && nodeConfig == "" {
				return
			} else if strings.Contains(err.Error(), "Node config has no labels specified") && adqsetupConfig == "" && nodeConfig == "" {
				return
			} else if strings.Contains(err.Error(), "Node config FilterPrio") && adqsetupConfig == "" && nodeConfig == "" {
				return
			} else if strings.Contains(err.Error(), "If Rxusecs is set Rxadapt must be turned off") && adqsetupConfig == "" && nodeConfig == "" {
				return
			} else if strings.Contains(err.Error(), "If Txusecs is set Txadapt must be turned off") && adqsetupConfig == "" && nodeConfig == "" {
				return
			} else if strings.Contains(err.Error(), "Invalid Globals.Cpus value") && adqsetupConfig == "" && nodeConfig == "" {
				return
			} else if strings.Contains(err.Error(), "Invalid Globals.Numa value") && adqsetupConfig == "" && nodeConfig == "" {
				return
			} else if strings.Contains(err.Error(), "Invalid Cpus value") && adqsetupConfig == "" && nodeConfig == "" {
				return
			} else if strings.Contains(err.Error(), "Invalid Numa value") && adqsetupConfig == "" && nodeConfig == "" {
				return
			} else if strings.Contains(err.Error(), "Invalid egress mode") && adqsetupConfig == "" && nodeConfig == "" {
				return
			} else {
				t.Errorf("Error: %s, result: %s, for input %s", err.Error(), adqsetupConfig, string(fcfg))
			}
		} else { // OR valid result
			adqncfg := nodeconfigtypes.AdqNodeConfig{}
			err = json.Unmarshal([]byte(nodeConfig), &adqncfg)
			if err != nil {
				t.Errorf("Unable to unmarshall nodeconfig: %s", nodeConfig)
			}

			if adqncfg.Globals.Dev != masterInterface {
				t.Errorf("Invalid .Globals.Dev in result: %s, for input %s", adqncfg.Globals.Dev, string(fcfg))
			}

			if adqncfg.EgressMode != "skbedit" && adqncfg.EgressMode != "netprio" {
				t.Errorf("Invalid .EgressMode: %s, for input %s", adqncfg.EgressMode, string(fcfg))
			}

			return
		}
	})
}
