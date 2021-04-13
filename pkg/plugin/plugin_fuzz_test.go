package plugin

import (
	"strings"
	"testing"
)

func FuzzLoadConf(f *testing.F) {
	seed := `
	{
        "name": "chained",
        "cniVersion": "0.3.1",
        "plugins": [
            {
                "type": "cilium-cni"
            },
            {
                "type": "adq-cni",
                "tunneling": "disabled",
                "tunneling-interface": ""
            }
        ]
    }
	`

	f.Add([]byte(seed))

	f.Fuzz(func(t *testing.T, fcfg []byte) {

		_, err := loadConf(fcfg)

		if err != nil {
			if strings.Contains(err.Error(), "Loading network configuration unsuccessful:") {
				return
			} else if strings.Contains(err.Error(), "unsupported \"tunneling\" value - can be empty or \"disabled\" or \"vxlan\"") {
				return
			} else if strings.Contains(err.Error(), "\"tunneling-interface\" can't be empty when tunneling is enabled") {
				return
			} else {
				t.Errorf("Error: %s, for input %s", err.Error(), string(fcfg))
			}
		} else {
			return
		}
	})
}
