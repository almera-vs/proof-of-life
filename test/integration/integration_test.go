//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/almera-vs/proof-of-life/internal/sandbox/docker"
	"github.com/almera-vs/proof-of-life/test/harness"
)

func requireNoOrphans(t *testing.T) {
	t.Helper()
	sb, err := docker.New("")
	if err != nil {
		t.Fatal(err)
	}
	res, err := sb.Collect(context.Background(), docker.GCOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Containers != 0 || res.Volumes != 0 {
		t.Fatalf("the drill left things behind: %+v", res)
	}
}

func TestPgBackRestHappyPath(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{Encrypted: true})
	s.Backup("full")
	s.Capture()
	s.SwitchWAL()
	if res := s.Workspace.Pol("validate", "-c", s.Workspace.Config); res.Exit != 0 {
		t.Fatalf("validate: %s\n%s", res.Stdout, res.Stderr)
	}
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	r := harness.RequirePass(t, s.Workspace, res)
	if r.Counts.Passed != 12 {
		t.Fatalf("passed = %d, want all 12\n%s", r.Counts.Passed, res.Stdout)
	}
	requireNoOrphans(t)
	s.Workspace.VerifyEvidence()
	if !strings.Contains(res.Stdout, "RESTORABLE") || !strings.Contains(res.Stdout, "exit 0") {
		t.Errorf("no verdict line:\n%s", res.Stdout)
	}
}

func TestPITRToATimeAndAnLSN(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.Backup("full")
	s.Capture()
	s.SQL("INSERT INTO audit_log (payload) VALUES ('before target')")
	time.Sleep(1100 * time.Millisecond)
	target := time.Now().UTC().Format(time.RFC3339)
	lsn := s.SQL("SELECT pg_current_wal_lsn()")
	time.Sleep(1100 * time.Millisecond)
	s.SQL("INSERT INTO audit_log (payload) VALUES ('after target')")
	s.SwitchWAL()

	res := s.Workspace.Pol("run", "-c", s.Workspace.Config, "--target-time", target)
	r := harness.RequirePass(t, s.Workspace, res)
	if c := harness.Check(t, r, "recovery.pitr_target"); c.Status != "pass" {
		t.Fatalf("%+v", c)
	}
	if r.RecoveryPoint.Time == nil || r.RecoveryPoint.Time.Format(time.RFC3339) > target {
		t.Fatalf("recovered past the target %s: %+v", target, r.RecoveryPoint)
	}

	cfg, err := os.ReadFile(s.Workspace.Config)
	if err != nil {
		t.Fatal(err)
	}
	withLSN := strings.Replace(string(cfg), "recovery: { target: latest }", fmt.Sprintf(`recovery: { target: { lsn: "%s" } }`, lsn), 1)
	if err := os.WriteFile(s.Workspace.Config, []byte(withLSN), 0o600); err != nil {
		t.Fatal(err)
	}
	r = harness.RequirePass(t, s.Workspace, s.Workspace.Pol("run", "-c", s.Workspace.Config))
	if c := harness.Check(t, r, "recovery.pitr_target"); !strings.Contains(c.Observed, "reached") {
		t.Fatalf("%+v", c)
	}
}

func TestPITRTargetBeyondTheArchiveFails(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.Backup("full")
	s.Capture()
	s.SwitchWAL()
	future := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config, "--target-time", future)
	harness.RequireFail(t, s.Workspace, res, "recovery.pitr_target", "before reaching the target")
}

func TestHeartbeatProvesRecoveryPoint(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.WriteDrill(harness.DrillOptions{Heartbeat: true})
	if res := s.Workspace.Pol("fingerprint", "heartbeat", "-c", s.Workspace.Config, "--once"); res.Exit != 0 {
		t.Fatalf("heartbeat: %s %s", res.Stdout, res.Stderr)
	}
	s.Backup("full")
	s.Capture()
	if res := s.Workspace.Pol("fingerprint", "heartbeat", "-c", s.Workspace.Config, "--once"); res.Exit != 0 {
		t.Fatalf("heartbeat: %s %s", res.Stdout, res.Stderr)
	}
	s.SwitchWAL()
	r := harness.RequirePass(t, s.Workspace, s.Workspace.Pol("run", "-c", s.Workspace.Config))
	c := harness.Check(t, r, "recovery.pitr_target")
	if !strings.Contains(c.Observed, "heartbeat") {
		t.Fatalf("the heartbeat was not checked: %+v", c)
	}
}

func TestPgDumpCustomFormat(t *testing.T) {
	s := harness.NewDumpStack(t, harness.Major())
	s.Dump("billing-1.dump", "c")
	s.Capture()
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	r := harness.RequirePass(t, s.Workspace, res)
	for _, id := range []string{"backup.integrity", "tooling.version_drift", "restore.completes", "server.starts", "schema.fingerprint", "data.row_counts", "data.assertions", "integrity.amcheck", "rto.within_target", "backup.freshness"} {
		if c := harness.Check(t, r, id); c.Status != "pass" {
			t.Errorf("%s = %s (%s)", id, c.Status, c.Reason)
		}
	}
	for _, id := range []string{"recovery.wal_continuity", "recovery.pitr_target"} {
		if c := harness.Check(t, r, id); c.Status != "skipped" {
			t.Errorf("%s = %s; a dump has no WAL", id, c.Status)
		}
	}
	requireNoOrphans(t)
	s.Workspace.VerifyEvidence()
}

func TestPgDumpDirectoryFormat(t *testing.T) {
	s := harness.NewDumpStack(t, harness.Major())
	s.Dump("billing-1.dir", "d")
	s.Capture()
	r := harness.RequirePass(t, s.Workspace, s.Workspace.Pol("run", "-c", s.Workspace.Config))
	if r.Backup.Label != "billing-1.dir" {
		t.Fatalf("%+v", r.Backup)
	}
}

func TestEditedEvidenceIsDetectedEndToEnd(t *testing.T) {
	s := harness.NewDumpStack(t, harness.Major())
	s.Dump("billing-1.dump", "c")
	s.Capture()
	w := s.Workspace
	harness.RequirePass(t, w, w.Pol("run", "-c", w.Config))
	harness.RequirePass(t, w, w.Pol("run", "-c", w.Config))
	w.VerifyEvidence()
	b, err := os.ReadFile(w.EvidencePath())
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(b), `"verdict":"pass"`, `"verdict":"fail"`, 1)
	if err := os.WriteFile(w.EvidencePath(), []byte(edited), 0o640); err != nil {
		t.Fatal(err)
	}
	res := w.Pol("evidence", "verify", "--log", w.EvidencePath(), "--pub", w.PubPath())
	if res.Exit != 1 || !strings.Contains(res.Stdout, "NOT VERIFIED") {
		t.Fatalf("exit %d: %s", res.Exit, res.Stdout)
	}

	again := w.Pol("run", "-c", w.Config)
	if again.Exit != 4 || !strings.Contains(again.Stdout, "evidence") {
		t.Fatalf("exit %d:\n%s", again.Exit, again.Stdout)
	}
}

func TestConfigErrorsExitThree(t *testing.T) {
	w := harness.NewWorkspace(t)
	w.WriteConfig("version: 1\nsource: { type: pgbackrest, repo: { type: s3 } }\n")
	res := w.Pol("validate", "-c", w.Config)
	if res.Exit != 3 || !strings.Contains(res.Stderr, "source.repo.bucket: required") {
		t.Fatalf("exit %d: %s", res.Exit, res.Stderr)
	}
}
