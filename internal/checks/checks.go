package checks

import (
	"context"
	"time"

	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/fingerprint"
	"github.com/almera-vs/proof-of-life/internal/sandbox"
	"github.com/almera-vs/proof-of-life/internal/source"
)

type Status string

const (
	Pass    Status = "pass"
	Fail    Status = "fail"
	Warn    Status = "warn"
	Skipped Status = "skipped"
)

type Severity string

const (
	Critical Severity = "critical"

	Major Severity = "major"
)

type ControlRef string

const (
	DORA ControlRef = "DORA Art. 12(2)"
	ISO  ControlRef = "ISO/IEC 27001:2022 A.8.13"
	SOC2 ControlRef = "SOC 2 A1.3"
	NIS2 ControlRef = "NIS2 Art. 21(2)(c)"
)

type Check interface {
	ID() string
	Controls() []ControlRef
	Run(ctx context.Context, env *Env) CheckResult
}

type Described interface {
	Severity() Severity
	Proves() string
}

type CheckResult struct {
	ID       string         `json:"id"`
	Status   Status         `json:"status"`
	Severity Severity       `json:"severity"`
	Proves   string         `json:"proves"`
	Observed string         `json:"observed"`
	Reason   string         `json:"reason,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
	Controls []ControlRef   `json:"controls"`
	Seconds  float64        `json:"seconds"`
}

type ServerFacts struct {
	Version    string
	VersionNum int
	Major      int
	InRecovery bool
	ReplayTime time.Time
	ReplayLSN  string
}

type Env struct {
	Cfg    *config.Config
	Now    time.Time
	Target source.RecoveryTarget

	Source       source.BackupSource
	Ref          source.BackupRef
	Meta         *source.BackupMeta
	SelectErr    error
	Inst         sandbox.Instance
	ProvisionErr error

	RestoreStarted bool
	RestoreErr     error
	RestoreTime    time.Duration

	Recovery    *source.RecoveryResult
	RecoveryErr error

	ServerErr error
	Server    *ServerFacts

	Catalog   fingerprint.Querier
	User      fingerprint.Querier
	Exec      func(ctx context.Context, argv []string) (sandbox.ExecResult, error)
	Superuser string
	Database  string

	Fingerprint *fingerprint.Snapshot

	FingerprintExact bool
	FingerprintErr   error

	RTO        time.Duration
	RTOReached bool
}

type simple struct {
	id       string
	proves   string
	severity Severity
	controls []ControlRef
	run      func(ctx context.Context, env *Env) CheckResult
}

func (s simple) ID() string             { return s.id }
func (s simple) Controls() []ControlRef { return s.controls }
func (s simple) Severity() Severity     { return s.severity }
func (s simple) Proves() string         { return s.proves }
func (s simple) Run(ctx context.Context, env *Env) CheckResult {
	return s.run(ctx, env)
}

func pass(observed string) CheckResult { return CheckResult{Status: Pass, Observed: observed} }

func fail(observed, reason string) CheckResult {
	return CheckResult{Status: Fail, Observed: observed, Reason: reason}
}

func warn(observed, reason string) CheckResult {
	return CheckResult{Status: Warn, Observed: observed, Reason: reason}
}

func skip(reason string) CheckResult {
	return CheckResult{Status: Skipped, Observed: "not run", Reason: reason}
}

func RunAll(ctx context.Context, all []Check, env *Env) []CheckResult {
	out := make([]CheckResult, 0, len(all))
	for _, c := range all {
		start := time.Now()
		r := runOne(ctx, c, env)
		r.ID, r.Controls = c.ID(), c.Controls()
		if d, ok := c.(Described); ok {
			r.Severity, r.Proves = d.Severity(), d.Proves()
		}
		r.Seconds = time.Since(start).Seconds()
		out = append(out, r)
	}
	return out
}

func runOne(ctx context.Context, c Check, env *Env) (r CheckResult) {
	defer func() {
		if p := recover(); p != nil {
			r = fail("check crashed", "This check stopped unexpectedly, so its result cannot be trusted.")
		}
	}()
	return c.Run(ctx, env)
}

func (e *Env) ServerReady() bool { return e.Server != nil && e.ServerErr == nil }

func All() []Check {
	return []Check{
		backupFreshness,
		backupIntegrity,
		versionDrift,
		restoreCompletes,
		walContinuity,
		pitrTarget,
		serverStarts,
		schemaFingerprint,
		dataRowCounts,
		dataAssertions,
		amcheck,
		rtoWithinTarget,
	}
}
