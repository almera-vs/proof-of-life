//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"

	"github.com/almera-vs/proof-of-life/internal/sandbox/docker"
	"github.com/almera-vs/proof-of-life/test/harness"
)

func TestPgBackRestPosixRepository(t *testing.T) {

	repo, err := os.MkdirTemp("", "pol-posix-repo-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(repo) })
	if err := os.Chmod(repo, 0o777); err != nil {
		t.Fatal(err)
	}
	s := harness.NewStack(t, harness.StackOptions{PosixRepo: repo})
	s.Backup("full")
	s.Capture()
	s.SwitchWAL()
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	r := harness.RequirePass(t, s.Workspace, res)
	if r.Counts.Passed != 12 {
		t.Fatalf("passed = %d\n%s", r.Counts.Passed, res.Stdout)
	}
}

func TestPgDumpFromS3(t *testing.T) {
	for _, format := range []string{"c", "d"} {
		t.Run(format, func(t *testing.T) {
			stack := harness.NewStack(t, harness.StackOptions{})
			dump := harness.NewDumpStack(t, harness.Major())
			name := "billing-1." + format
			local := dump.Dump(name, format)
			upload(t, stack, local, "dumps/"+name)
			host, port := stack.S3Address(t)
			w := dump.Workspace
			w.Env = append(w.Env, stack.Workspace.Env...)
			w.Env = append(w.Env, "POL_DSN="+dump.DSN)
			w.WriteConfig(fmt.Sprintf(`version: 1
drill: { name: billing, rto_target: 30m, restore_timeout: 15m }
source:
  type: pgdump
  pattern: "billing-*"
  repo:
    type: s3
    bucket: %s
    region: us-east-1
    path: /dumps
    endpoint: %s
    port: %s
    uri_style: path
    verify_tls: false
    credentials: { from_env: true }
fingerprint:
  dsn: { env: POL_DSN }
  exact_count_tables: [public.customers]
  row_count_tolerance: 0.5%%
sandbox: { image: "postgres:{{major}}", cpus: 2, memory: 2GiB }
checks: { amcheck: { enabled: true, time_budget: 5m } }
`, harness.Bucket, host, port))
			dump.Capture()
			r := harness.RequirePass(t, w, w.Pol("run", "-c", w.Config))
			if r.Backup.Label != name {
				t.Fatalf("%+v", r.Backup)
			}
			if c := harness.Check(t, r, "schema.fingerprint"); c.Status != "pass" {
				t.Fatalf("%+v", c)
			}
		})
	}
}

func upload(t *testing.T, s *harness.Stack, local, key string) {
	t.Helper()
	info, err := os.Stat(local)
	if err != nil {
		t.Fatal(err)
	}
	put := func(path, k string, size int64) {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := s.S3.PutObject(context.Background(), harness.Bucket, k, f, size, minio.PutObjectOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if !info.IsDir() {
		put(local, key, info.Size())
		return
	}
	entries, err := os.ReadDir(local)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		put(filepath.Join(local, e.Name()), key+"/"+e.Name(), fi.Size())
	}
}

func waitForSandbox(t *testing.T) *docker.Sandbox {
	t.Helper()
	sb, err := docker.New("")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		res, err := sb.Collect(context.Background(), docker.GCOptions{DryRun: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Skipped) > 0 {
			return sb
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the drill never created a sandbox")
	return nil
}

func TestSignalsTearDownTheSandbox(t *testing.T) {
	for name, sig := range map[string]syscall.Signal{"SIGTERM": syscall.SIGTERM, "SIGINT": syscall.SIGINT} {
		t.Run(name, func(t *testing.T) {
			s := harness.NewDumpStack(t, harness.Major())
			s.Dump("billing-1.dump", "c")
			s.Capture()
			cmd := s.Workspace.Start("run", "-c", s.Workspace.Config)
			waitForSandbox(t)
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			err := cmd.Wait()
			if err == nil {
				t.Fatal("an interrupted drill must not exit 0")
			}
			requireNoOrphans(t)
		})
	}
}

func TestKeepSandboxOnFail(t *testing.T) {
	s := harness.NewDumpStack(t, harness.Major())
	path := s.Dump("billing-1.dump", "c")
	s.Capture()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, info.Size()/2); err != nil {
		t.Fatal(err)
	}
	w := s.Workspace
	res := w.Pol("run", "-c", w.Config, "--keep-sandbox-on-fail")
	harness.RequireFail(t, w, res, "restore.completes", "pg_restore stopped")
	sb, err := docker.New("")
	if err != nil {
		t.Fatal(err)
	}
	found, err := sb.Collect(context.Background(), docker.GCOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(found.Skipped) == 0 || !strings.Contains(found.Skipped[0], "kept") {
		t.Fatalf("the sandbox should have been kept, and gc should leave it: %+v", found)
	}
	if gc := w.Pol("gc", "--all"); gc.Exit != 0 {
		t.Fatalf("gc --all: %s %s", gc.Stdout, gc.Stderr)
	}
	requireNoOrphans(t)
}

func TestNotificationsMetricsAndReportShow(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var b bytes.Buffer
		_, _ = b.ReadFrom(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b.Bytes(), &m)
		mu.Lock()
		bodies = append(bodies, m)
		mu.Unlock()
	}))
	defer srv.Close()

	s := harness.NewDumpStack(t, harness.Major())
	path := s.Dump("billing-1.dump", "c")
	s.Capture()
	w := s.Workspace
	prom := filepath.Join(w.Dir, "pol.prom")
	cfg, err := os.ReadFile(w.Config)
	if err != nil {
		t.Fatal(err)
	}
	extra := fmt.Sprintf("notify: { on: [fail, warn], webhook: { url: { env: POL_HOOK } }, slack: { webhook: { env: POL_HOOK } } }\nmetrics: { textfile: %s }\n", prom)
	if err := os.WriteFile(w.Config, append(cfg, extra...), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Env = append(w.Env, "POL_HOOK="+srv.URL)

	first := w.Pol("run", "-c", w.Config)
	r := harness.RequirePass(t, w, first)
	if len(bodies) != 0 {
		t.Fatalf("a pass should not notify: %+v", bodies)
	}
	metrics, err := os.ReadFile(prom)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(metrics), `pol_drill_status{drill="billing",status="pass"} 1`) {
		t.Fatalf("metrics:\n%s", metrics)
	}

	shown := w.Pol("report", "show", r.RunID, "-c", w.Config, "--format", "json")
	if shown.Exit != 0 || !strings.Contains(shown.Stdout, `"schema_version": 1`) {
		t.Fatalf("report show json: %d %s %s", shown.Exit, shown.Stdout, shown.Stderr)
	}
	shown = w.Pol("report", "show", r.RunID, "-c", w.Config, "--format", "html")
	if shown.Exit != 0 || !strings.HasPrefix(shown.Stdout, "<!doctype html>") {
		t.Fatalf("report show html: %d %s", shown.Exit, shown.Stderr)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, info.Size()/2); err != nil {
		t.Fatal(err)
	}
	harness.RequireFail(t, w, w.Pol("run", "-c", w.Config), "restore.completes", "pg_restore stopped")
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("expected a webhook and a Slack message, got %d", len(bodies))
	}
	for _, b := range bodies {
		text := fmt.Sprint(b)
		if !strings.Contains(text, "Not restorable") || strings.Contains(text, harness.Sentinel) {
			t.Errorf("%s", text)
		}
	}
}

func TestUndeliveredNotificationExitsFour(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	s := harness.NewDumpStack(t, harness.Major())
	s.Dump("billing-1.dump", "c")
	s.Capture()
	w := s.Workspace
	cfg, err := os.ReadFile(w.Config)
	if err != nil {
		t.Fatal(err)
	}
	extra := "notify: { on: [pass], webhook: { url: { env: POL_HOOK } } }\n"
	if err := os.WriteFile(w.Config, append(cfg, extra...), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Env = append(w.Env, "POL_HOOK=http://"+addr+"/hook")
	res := w.Pol("run", "-c", w.Config)
	if res.Exit != 4 || !strings.Contains(res.Stdout, "RESTORABLE") || !strings.Contains(res.Stdout, "delivery") {
		t.Fatalf("exit %d:\n%s", res.Exit, res.Stdout)
	}
	if strings.Contains(res.Stdout+res.Stderr, addr) {
		t.Error("the webhook address leaked into the output")
	}
}
