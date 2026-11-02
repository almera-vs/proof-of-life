//go:build integration

package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type SandboxContainer struct {
	ID     string
	Image  string
	Config struct {
		User       string
		Entrypoint []string
	}
	HostConfig struct {
		NetworkMode    string
		Privileged     bool
		ReadonlyRootfs bool
		CapDrop        []string
		SecurityOpt    []string
		Memory         int64
		NanoCpus       int64
		PidsLimit      int64
	}
}

func (c SandboxContainer) IsServer() bool {
	return len(c.Config.Entrypoint) > 0 && c.Config.Entrypoint[0] == "postgres"
}

func dockerGet(ctx context.Context, path string, q url.Values, out any) error {
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", "/var/run/docker.sock")
	}}}
	u := "http://docker/v1.44" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker answered %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func WatchSandboxes(t *testing.T) (stop func() []SandboxContainer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	seen := map[string]SandboxContainer{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			var list []struct {
				ID string `json:"Id"`
			}
			q := url.Values{"all": {"1"}, "filters": {`{"label":["pol.run_id"]}`}}
			if err := dockerGet(ctx, "/containers/json", q, &list); err == nil {
				for _, c := range list {
					mu.Lock()
					_, known := seen[c.ID]
					mu.Unlock()
					if known {
						continue
					}
					var full SandboxContainer
					if err := dockerGet(ctx, "/containers/"+c.ID+"/json", nil, &full); err == nil {
						mu.Lock()
						seen[c.ID] = full
						mu.Unlock()
					}
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	return func() []SandboxContainer {
		cancel()
		<-done
		mu.Lock()
		defer mu.Unlock()
		out := make([]SandboxContainer, 0, len(seen))
		for _, c := range seen {
			out = append(out, c)
		}
		return out
	}
}

func RequireConfined(t *testing.T, c SandboxContainer) {
	t.Helper()
	h := c.HostConfig
	name := strings.Join(c.Config.Entrypoint, " ")
	if c.Config.User != "999:999" {
		t.Errorf("%s runs as %q", name, c.Config.User)
	}
	if h.Privileged {
		t.Errorf("%s is privileged", name)
	}
	if !h.ReadonlyRootfs {
		t.Errorf("%s has a writable root filesystem", name)
	}
	if len(h.CapDrop) != 1 || h.CapDrop[0] != "ALL" {
		t.Errorf("%s keeps capabilities: %v", name, h.CapDrop)
	}
	found := false
	for _, o := range h.SecurityOpt {
		found = found || strings.HasPrefix(o, "no-new-privileges")
	}
	if !found {
		t.Errorf("%s allows privilege escalation: %v", name, h.SecurityOpt)
	}
	if h.Memory <= 0 || h.NanoCpus <= 0 || h.PidsLimit <= 0 {
		t.Errorf("%s has no limits: memory %d, cpus %d, pids %d", name, h.Memory, h.NanoCpus, h.PidsLimit)
	}
}
