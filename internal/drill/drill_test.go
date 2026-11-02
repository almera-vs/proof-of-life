package drill

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/almera-vs/proof-of-life/internal/checks"
	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/sandbox"
	"github.com/almera-vs/proof-of-life/internal/source"
)

func TestDecideFailsClosed(t *testing.T) {
	ok := func(id string) checks.CheckResult { return checks.CheckResult{ID: id, Status: checks.Pass} }
	base := []checks.CheckResult{ok("restore.completes"), ok("server.starts")}
	cases := []struct {
		name  string
		in    []checks.CheckResult
		infra error
		want  Verdict
	}{
		{"all pass", base, nil, VerdictPass},
		{"skipped optional still passes", append(base[:2:2], checks.CheckResult{ID: "data.assertions", Status: checks.Skipped}), nil, VerdictPass},
		{"warning", append(base[:2:2], checks.CheckResult{ID: "x", Status: checks.Warn}), nil, VerdictWarn},
		{"failure beats warning", append(base[:2:2], checks.CheckResult{ID: "x", Status: checks.Warn}, checks.CheckResult{ID: "y", Status: checks.Fail}), nil, VerdictFail},
		{"nothing ran", nil, nil, VerdictFail},
		{"restore skipped", []checks.CheckResult{{ID: "restore.completes", Status: checks.Skipped}, ok("server.starts")}, nil, VerdictFail},
		{"server skipped", []checks.CheckResult{ok("restore.completes"), {ID: "server.starts", Status: checks.Skipped}}, nil, VerdictFail},
		{"infrastructure error", base, errors.New("daemon gone"), VerdictFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Decide(tc.in, tc.infra); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

type fakeInstance struct{ sandbox.Instance }

func (fakeInstance) ID() string { return "inst" }

type fakeSandbox struct {
	destroyed   []string
	createErr   error
	interrupted bool
}

func (f *fakeSandbox) Create(context.Context, sandbox.Spec) (sandbox.Instance, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	return fakeInstance{}, nil
}

func (f *fakeSandbox) Destroy(ctx context.Context, id string) error {
	f.interrupted = ctx.Err() != nil
	f.destroyed = append(f.destroyed, id)
	return nil
}

type fakeSource struct {
	restore func(ctx context.Context) error
}

func (f fakeSource) Latest(context.Context) (source.BackupRef, error) {
	return source.BackupRef{Label: "b1"}, nil
}

func (f fakeSource) Describe(context.Context, source.BackupRef) (source.BackupMeta, error) {
	return source.BackupMeta{Label: "b1", PGMajor: 17}, nil
}

func (f fakeSource) Restore(ctx context.Context, _ source.BackupRef, _ source.RestoreTarget, _ sandbox.Instance) (source.RestoreResult, error) {
	return source.RestoreResult{}, f.restore(ctx)
}

func (f fakeSource) Verify(context.Context, source.BackupRef, sandbox.Instance) (source.VerifyResult, error) {
	return source.VerifyResult{OK: true}, nil
}

func options(src source.BackupSource, sb sandbox.Sandbox) Options {
	cfg := &config.Config{}
	cfg.Drill.Name = "d"
	cfg.Drill.RestoreTimeout = config.Duration(time.Hour)
	cfg.Sandbox.Image = "postgres:{{major}}"
	return Options{
		Config: cfg, Source: src, Sandbox: sb, Checks: checks.All(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Progress: Discard{},
	}
}

func TestTeardownRunsOnFailure(t *testing.T) {
	sb := &fakeSandbox{}
	res := Run(context.Background(), "r1", options(fakeSource{restore: func(context.Context) error {
		return source.Failf(source.FailRestore, "truncated")
	}}, sb))
	if len(sb.destroyed) != 1 {
		t.Fatalf("destroyed = %v", sb.destroyed)
	}
	if res.Verdict != VerdictFail || res.InfraErr != nil {
		t.Fatalf("verdict=%s infra=%v", res.Verdict, res.InfraErr)
	}
}

func TestTeardownRunsOnPanic(t *testing.T) {
	sb := &fakeSandbox{}
	res := Run(context.Background(), "r1", options(fakeSource{restore: func(context.Context) error {
		panic("boom")
	}}, sb))
	if len(sb.destroyed) != 1 {
		t.Fatalf("destroyed = %v", sb.destroyed)
	}
	if res.Verdict != VerdictFail {
		t.Fatalf("verdict = %s", res.Verdict)
	}
}

func TestTeardownRunsOnCancellation(t *testing.T) {
	sb := &fakeSandbox{}
	ctx, cancel := context.WithCancel(context.Background())
	res := Run(ctx, "r1", options(fakeSource{restore: func(ctx context.Context) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}}, sb))
	if len(sb.destroyed) != 1 {
		t.Fatalf("destroyed = %v", sb.destroyed)
	}
	if res.Verdict != VerdictFail {
		t.Fatalf("verdict = %s", res.Verdict)
	}

	if !sb.interrupted {
		t.Fatal("teardown hid the cancellation from the sandbox")
	}
}

func TestSandboxKeptOnlyWhenAskedAndFailed(t *testing.T) {
	sb := &fakeSandbox{}
	kept := 0
	o := options(fakeSource{restore: func(context.Context) error {
		return source.Failf(source.FailRestore, "truncated")
	}}, sb)
	o.KeepSandboxOnFail = true
	o.Keep = func(context.Context, string, string) error { kept++; return nil }
	Run(context.Background(), "r1", o)
	if len(sb.destroyed) != 0 || kept != 1 {
		t.Fatalf("destroyed=%v kept=%d", sb.destroyed, kept)
	}
}

func TestRestoreTimeoutIsACheckFailureNotInfrastructure(t *testing.T) {
	o := options(fakeSource{restore: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}, &fakeSandbox{})
	o.Config.Drill.RestoreTimeout = config.Duration(10 * time.Millisecond)
	res := Run(context.Background(), "r1", o)
	if res.InfraErr != nil {
		t.Fatalf("infra = %v", res.InfraErr)
	}
	for _, c := range res.Checks {
		if c.ID == "restore.completes" && c.Status != checks.Fail {
			t.Fatalf("restore.completes = %s", c.Status)
		}
	}
	if res.Verdict != VerdictFail {
		t.Fatalf("verdict = %s", res.Verdict)
	}
}

type slowImages struct {
	fakeSandbox
	delay time.Duration
	calls int
}

func (s *slowImages) EnsureImage(context.Context, string, []byte) error {
	s.calls++
	time.Sleep(s.delay)
	return nil
}

type preparedSource struct {
	fakeSource
	delay time.Duration
}

func (p preparedSource) Prepare(context.Context) error {
	time.Sleep(p.delay)
	return nil
}

func TestImagePreparationIsNotInRTO(t *testing.T) {
	const delay = 300 * time.Millisecond
	sb := &slowImages{delay: delay}
	src := preparedSource{fakeSource: fakeSource{restore: func(context.Context) error {
		return source.Failf(source.FailRestore, "stop here")
	}}, delay: delay}
	res := Run(context.Background(), "r1", options(src, sb))
	if sb.calls != 1 {
		t.Fatalf("the sandbox image was prepared %d times", sb.calls)
	}
	if res.RTO >= delay {
		t.Fatalf("RTO %s includes image preparation", res.RTO)
	}
	seen := 0
	for _, p := range res.Phases {
		if p.Name == PhaseImages {
			seen++
		}
	}
	if seen != 2 {
		t.Fatalf("the time should still be recorded, as its own phase: %+v", res.Phases)
	}
}

func TestProvisionFailureIsInfrastructure(t *testing.T) {
	res := Run(context.Background(), "r1", options(fakeSource{restore: func(context.Context) error { return nil }},
		&fakeSandbox{createErr: errors.New("daemon gone")}))
	if res.InfraErr == nil || res.Verdict != VerdictFail {
		t.Fatalf("infra=%v verdict=%s", res.InfraErr, res.Verdict)
	}
}
