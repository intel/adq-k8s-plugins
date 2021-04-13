package kubeletclient

import (
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func FuzzLoadAnnotation(f *testing.F) {
	seed := `'[ { "name": "redis", "ports": { "local": ["6379/  TCP"] } } ]'`

	f.Add([]byte(seed))

	f.Fuzz(func(t *testing.T, fcfg []byte) {
		string_annotation := string(fcfg)
		pod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"net.v1.intel.com/adq-config": string_annotation,
				},
			},
		}

		kc, _ := GetKubeletHTTPClient("", "", "")
		_, err := kc.getAnnotationConfig(pod)

		if err != nil {
			if strings.Contains(err.Error(), "annotation with ADQ config not in JSON format") {
				return
			} else if strings.Contains(err.Error(), "invalid character") {
				return
			} else {
				t.Errorf("Error: %s, for input: %s", err.Error(), string(fcfg))
			}
		} else {
			return
		}
	})
}
