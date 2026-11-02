package docker

import (
	"strings"
	"testing"
)

func TestRemoteDaemonOverPlainTCPIsRefused(t *testing.T) {
	for _, host := range []string{"tcp://10.0.0.5:2375", "tcp://docker.internal:2375", "http://192.168.1.2:2375"} {
		if _, err := newClient(host); err == nil || !strings.Contains(err.Error(), "remote daemon") {
			t.Errorf("%s: %v", host, err)
		}
	}
	for _, host := range []string{"tcp://127.0.0.1:2375", "tcp://localhost:2375", "tcp://[::1]:2375", "unix:///var/run/docker.sock"} {
		if _, err := newClient(host); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
	if _, err := newClient("ssh://host"); err == nil {
		t.Error("an unsupported scheme must be refused")
	}
}
