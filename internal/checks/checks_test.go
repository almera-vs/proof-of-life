package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/sandbox"
	"github.com/almera-vs/proof-of-life/internal/source"
)

func TestAllChecksHaveStableIDsAndDescriptions(t *testing.T) {
	want := []string{
		"backup.freshness", "backup.integrity", "tooling.version_drift", "restore.completes",
		"recovery.wal_continuity", "recovery.pitr_target", "server.starts", "schema.fingerprint",
		"data.row_counts", "data.assertions", "integrity.amcheck", "rto.within_target",
	}
	all := All()
	if len(all) != len(want) {
		t.Fatalf("got %d checks", len(all))
	}
	for i, c := range all {
		if c.ID() != want[i] {
			t.Errorf("position %d: got %s want %s", i, c.ID(), want[i])
		}
		if len(c.Controls()) == 0 {
			t.Errorf("%s has no controls", c.ID())
		}
		d := c.(Described)
		if d.Severity() == "" || d.Proves() == "" {
			t.Errorf("%s lacks a description", c.ID())
		}
	}
}

func baseEnv() *Env {
	cfg := &config.Config{}
	cfg.Drill.MaxAge = config.Duration(26 * time.Hour)
	cfg.Drill.RTOTarget = config.Duration(30 * time.Minute)
	return &Env{Cfg: cfg, Now: time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)}
}

func TestFreshness(t *testing.T) {
	env := baseEnv()
	if r := backupFreshness.Run(context.Background(), env); r.Status != Fail {
		t.Errorf("no backup: %s", r.Status)
	}
	env.Meta = &source.BackupMeta{StopTime: env.Now.Add(-14 * time.Minute)}
	if r := backupFreshness.Run(context.Background(), env); r.Status != Pass || r.Observed != "14m 00s old · max 26h" {
		t.Errorf("%+v", r)
	}
	env.Meta.StopTime = env.Now.Add(-27 * time.Hour)
	if r := backupFreshness.Run(context.Background(), env); r.Status != Fail || !strings.Contains(r.Reason, "older than max_age") {
		t.Errorf("%+v", r)
	}
}

func TestRTO(t *testing.T) {
	env := baseEnv()
	if r := rtoWithinTarget.Run(context.Background(), env); r.Status != Skipped {
		t.Errorf("no restore attempted: %+v", r)
	}
	env.RestoreStarted = true
	if r := rtoWithinTarget.Run(context.Background(), env); r.Status != Fail {
		t.Errorf("unreached RTO must fail: %+v", r)
	}
	env.RTOReached, env.RTO = true, 13*time.Minute+5*time.Second
	if r := rtoWithinTarget.Run(context.Background(), env); r.Status != Pass || r.Observed != "13m 05s of 30m" {
		t.Errorf("%+v", r)
	}
	env.RTO = 31 * time.Minute
	if r := rtoWithinTarget.Run(context.Background(), env); r.Status != Fail {
		t.Errorf("%+v", r)
	}
}

func TestVersionDriftCatchesGitLabCase(t *testing.T) {
	cases := []struct {
		name string
		meta source.BackupMeta
		prod int
		want Status
		text string
	}{
		{"same", source.BackupMeta{Tool: "pg_dump", ToolMajor: 17, PGMajor: 17}, 17, Pass, ""},
		{"newer tool", source.BackupMeta{Tool: "pg_dump", ToolMajor: 18, PGMajor: 17}, 17, Pass, ""},
		{"older tool", source.BackupMeta{Tool: "pg_dump", ToolMajor: 16, PGMajor: 17}, 17, Fail, "must be at least as new"},
		{"empty archive", source.BackupMeta{Tool: "pg_dump", Label: "x.dump"}, 17, Fail, "refuses to dump a newer server"},
		{"empty archive no reference", source.BackupMeta{Tool: "pg_dump", Label: "x.dump"}, 0, Fail, "cannot be identified"},
		{"stale after upgrade", source.BackupMeta{Tool: "pg_dump", ToolMajor: 16, PGMajor: 16}, 17, Fail, "since the upgrade"},
		{"pgbackrest ok", source.BackupMeta{Tool: "pgBackRest", ToolVersion: "2.60.0", RestoreToolVersion: "2.60.0", PGMajor: 18}, 18, Pass, ""},
		{"pgbackrest too old", source.BackupMeta{Tool: "pgBackRest", ToolVersion: "2.40", RestoreToolVersion: "2.60.0", PGMajor: 18}, 18, Fail, "needs at least 2.55"},
		{"pgbackrest stale stanza", source.BackupMeta{Tool: "pgBackRest", ToolVersion: "2.60.0", RestoreToolVersion: "2.60.0", PGMajor: 16}, 17, Fail, "stanza was upgraded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r CheckResult
			if tc.meta.Tool == "pg_dump" {
				r = dumpDrift(&tc.meta, tc.prod)
			} else {
				r = backrestDrift(&tc.meta, tc.prod)
			}
			if r.Status != tc.want || !strings.Contains(r.Reason, tc.text) {
				t.Fatalf("%+v", r)
			}
		})
	}
}

func TestHeartbeatWindow(t *testing.T) {
	target := time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC)
	interval := 30 * time.Second
	if err := CheckHeartbeat(target.Add(-13*time.Second), target, interval); err != nil {
		t.Errorf("inside: %v", err)
	}
	if err := CheckHeartbeat(target.Add(time.Second), target, interval); err == nil {
		t.Error("a heartbeat after the target means recovery overshot")
	}
	if err := CheckHeartbeat(target.Add(-5*time.Minute), target, interval); err == nil {
		t.Error("an old heartbeat means recovery fell short")
	}
}

func TestAmcheckResultNamesRelationsOnly(t *testing.T) {
	r := amcheckResult(sandbox.ExecResult{ExitCode: 2, Stdout: `heap table "billing.public.t", block 3, offset 7:
    xmin 12345 precedes relation freezexid 678
btree index "billing.public.t_pkey":
    ERROR:  item order invariant violated for index "t_pkey"
    DETAIL:  Lower index tid=(1,2) (points to heap tid=(3,4)) customer@example.com
`}, "1.0s")
	if r.Status != Fail {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.Reason, `heap table billing.public.t`) || !strings.Contains(r.Reason, `btree index billing.public.t_pkey`) {
		t.Errorf("%s", r.Reason)
	}
	if strings.Contains(r.Reason, "customer@example.com") {
		t.Error("detail lines leaked into the reason")
	}
	if r := amcheckResult(sandbox.ExecResult{ExitCode: 0}, "1.0s"); r.Status != Pass {
		t.Errorf("%+v", r)
	}
	if r := amcheckResult(sandbox.ExecResult{ExitCode: 1, Stderr: "connection failed"}, "1.0s"); r.Status != Fail {
		t.Errorf("a tool error must not pass: %+v", r)
	}
}

type logicalSource struct{ source.BackupSource }

func TestRecoveryChecksDoNotApplyToDumps(t *testing.T) {
	env := baseEnv()
	env.Source = logicalSource{}
	for _, c := range []simple{walContinuity, pitrTarget} {
		if r := c.Run(context.Background(), env); r.Status != Skipped {
			t.Errorf("%s: %+v", c.id, r)
		}
	}
}

type physicalSource struct{ source.BackupSource }

func (physicalSource) Recover(context.Context, source.BackupRef, source.RestoreTarget, sandbox.Instance) (source.RecoveryResult, error) {
	return source.RecoveryResult{}, nil
}

func TestWALGapAtLatestFails(t *testing.T) {
	env := baseEnv()
	env.Source = physicalSource{}
	env.Target = source.RecoveryTarget{Latest: true}
	env.Server = &ServerFacts{ReplayLSN: "0/9000000"}
	env.Recovery = &source.RecoveryResult{SegmentsNeeded: 5, Missing: []string{"000000010000000000000005"}}
	r := walContinuity.Run(context.Background(), env)
	if r.Status != Fail || !strings.Contains(r.Reason, "000000010000000000000005") {
		t.Fatalf("a server that started anyway must not hide the gap: %+v", r)
	}
}

func TestWALGapPastReachedTargetWarns(t *testing.T) {
	env := baseEnv()
	env.Source = physicalSource{}
	env.Target = source.RecoveryTarget{LSN: "0/4000000"}
	env.Server = &ServerFacts{ReplayLSN: "0/4000100"}
	env.Recovery = &source.RecoveryResult{SegmentsNeeded: 5, Missing: []string{"000000010000000000000009"}}
	if r := walContinuity.Run(context.Background(), env); r.Status != Warn {
		t.Fatalf("%+v", r)
	}
}

func TestReplayShortOfNewestSegmentFails(t *testing.T) {
	env := baseEnv()
	env.Source = physicalSource{}
	env.Target = source.RecoveryTarget{Latest: true}
	env.Server = &ServerFacts{ReplayLSN: "0/4000100"}
	env.Recovery = &source.RecoveryResult{SegmentsNeeded: 5, LastSegment: "000000010000000000000007", LastSegmentLSN: "0/7000000"}
	if r := walContinuity.Run(context.Background(), env); r.Status != Fail {
		t.Fatalf("%+v", r)
	}
}

func TestPITRFatalFails(t *testing.T) {
	env := baseEnv()
	env.Source = physicalSource{}
	env.Target = source.RecoveryTarget{Time: env.Now}
	env.Recovery = &source.RecoveryResult{ServerFatal: "recovery ended before configured recovery target was reached"}
	r := pitrTarget.Run(context.Background(), env)
	if r.Status != Fail || !strings.Contains(r.Reason, "recovery ended before") {
		t.Fatalf("%+v", r)
	}
}

func TestReferenceMissingFailsRatherThanSkips(t *testing.T) {
	env := baseEnv()
	env.Cfg.Fingerprint = &config.Fingerprint{}
	env.FingerprintErr = errNoneForTest()
	if r := schemaFingerprint.Run(context.Background(), env); r.Status != Fail {
		t.Fatalf("%+v", r)
	}
}

func TestRunOneTurnsPanicIntoFailure(t *testing.T) {
	boom := simple{id: "x", run: func(context.Context, *Env) CheckResult { panic("boom") }}
	got := RunAll(context.Background(), []Check{boom}, baseEnv())
	if got[0].Status != Fail {
		t.Fatalf("%+v", got[0])
	}
}
