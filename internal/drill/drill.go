package drill

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/almera-vs/proof-of-life/internal/checks"
	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/fingerprint"
	"github.com/almera-vs/proof-of-life/internal/sandbox"
	"github.com/almera-vs/proof-of-life/internal/source"
)

const (
	PhaseImages    = "prepare_images"
	PhaseSelect    = "select_backup"
	PhaseDescribe  = "describe"
	PhaseProvision = "provision_sandbox"
	PhaseRestore   = "restore"
	PhaseRecover   = "recover"
	PhaseStart     = "start"
	PhaseChecks    = "checks"
	PhaseEvidence  = "evidence"
	PhaseReport    = "report"
	PhaseNotify    = "notify"
	PhaseTeardown  = "teardown"
)

type PhaseStatus string

const (
	PhaseOK      PhaseStatus = "ok"
	PhaseFailed  PhaseStatus = "failed"
	PhaseSkipped PhaseStatus = "skipped"
)

type PhaseTiming struct {
	Name    string      `json:"name"`
	Status  PhaseStatus `json:"status"`
	Seconds float64     `json:"seconds"`
}

type Verdict string

const (
	VerdictPass Verdict = "pass"
	VerdictWarn Verdict = "warn"
	VerdictFail Verdict = "fail"
)

type Result struct {
	RunID    string
	Drill    string
	Started  time.Time
	Finished time.Time
	Verdict  Verdict
	Meta     *source.BackupMeta
	Target   source.RecoveryTarget
	Server   *checks.ServerFacts
	Recovery *source.RecoveryResult
	Checks   []checks.CheckResult
	Phases   []PhaseTiming

	RTO        time.Duration
	RTOReached bool

	InfraErr error

	FingerprintLabel string

	PostErr error

	TeardownErr error
}

type Options struct {
	Config            *config.Config
	Source            source.BackupSource
	Sandbox           sandbox.Sandbox
	Checks            []checks.Check
	Logger            *slog.Logger
	Progress          Progress
	Target            source.RecoveryTarget
	KeepSandboxOnFail bool

	Keep func(ctx context.Context, runID, id string) error

	AfterChecks func(ctx context.Context, res *Result, timed func(name string, fn func() error) error) error
}

type Progress interface {
	Begin(runID string)
	Backup(meta *source.BackupMeta, target source.RecoveryTarget)
	Phase(p PhaseTiming)
	Check(c checks.CheckResult)
}

func NewRunID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate run id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

type runner struct {
	opts Options
	cfg  *config.Config
	res  *Result
	env  *checks.Env
	log  *slog.Logger

	inst sandbox.Instance
}

func Run(ctx context.Context, runID string, opts Options) (res *Result) {
	r := &runner{
		opts: opts, cfg: opts.Config, log: opts.Logger.With("run_id", runID),
		res: &Result{RunID: runID, Drill: opts.Config.Drill.Name, Started: time.Now().UTC(), Target: opts.Target},
	}
	r.env = &checks.Env{Cfg: opts.Config, Target: opts.Target, Source: opts.Source, Superuser: opts.Config.Sandbox.Superuser}
	res = r.res
	opts.Progress.Begin(runID)
	defer func() {
		if p := recover(); p != nil {
			r.log.Error("drill panicked", "panic", fmt.Sprint(p))
			r.res.InfraErr = errors.Join(r.res.InfraErr, fmt.Errorf("the drill stopped unexpectedly: %v", p))
			r.res.Verdict = VerdictFail
		}
		r.teardown(ctx)
		r.res.Finished = time.Now().UTC()
	}()
	r.prepare(ctx)
	r.runChecks(ctx)
	if opts.AfterChecks != nil {
		if err := opts.AfterChecks(ctx, r.res, r.timed); err != nil {
			r.res.PostErr = err
		}
	}
	return res
}

func (r *runner) timed(name string, fn func() error) error {
	start := time.Now()
	err := fn()
	status := PhaseOK
	if err != nil {
		status = PhaseFailed
	}
	r.record(name, status, time.Since(start))
	return err
}

func (r *runner) record(name string, status PhaseStatus, d time.Duration) {
	p := PhaseTiming{Name: name, Status: status, Seconds: d.Seconds()}
	r.res.Phases = append(r.res.Phases, p)
	r.opts.Progress.Phase(p)
	r.log.Info("phase finished", "phase", name, "status", status, "seconds", d.Seconds())
}

func (r *runner) prepare(ctx context.Context) {
	if p, ok := r.opts.Source.(source.Preparer); ok {
		if err := r.timed(PhaseImages, func() error { return p.Prepare(ctx) }); err != nil {
			r.env.SelectErr = err
			r.res.InfraErr = errors.Join(r.res.InfraErr, fmt.Errorf("prepare the tool image: %w", err))
			return
		}
	}

	start := time.Now()
	var excluded time.Duration
	defer func() {
		r.res.RTO = time.Since(start) - excluded
		r.env.RTO = r.res.RTO
		r.env.RTOReached = r.res.RTOReached
	}()
	if !r.selectBackup(ctx) {
		return
	}
	if r.res.Meta.PGMajor == 0 {
		return
	}
	imageStart := time.Now()
	ok := r.prepareImage(ctx)
	excluded = time.Since(imageStart)
	if !ok || !r.provision(ctx) {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, r.cfg.Drill.RestoreTimeout.D())
	defer cancel()
	if !r.restore(rctx) {
		return
	}
	if !r.recover(rctx) {
		return
	}
	r.res.RTOReached = r.start(rctx)
}

func (r *runner) prepareImage(ctx context.Context) bool {
	ip, ok := r.opts.Sandbox.(sandbox.ImagePreparer)
	if !ok {
		return true
	}
	image := r.cfg.ImageFor(r.res.Meta.PGMajor)
	if err := r.timed(PhaseImages, func() error { return ip.EnsureImage(ctx, image, nil) }); err != nil {
		r.env.ProvisionErr = err
		r.res.InfraErr = errors.Join(r.res.InfraErr, fmt.Errorf("prepare the sandbox image: %w", err))
		r.log.Error("image preparation failed", "error", err.Error())
		return false
	}
	return true
}

func (r *runner) selectBackup(ctx context.Context) bool {
	var ref source.BackupRef
	err := r.timed(PhaseSelect, func() error {
		var err error
		ref, err = r.opts.Source.Latest(ctx)
		return err
	})
	if err != nil {
		r.noteSelectError(err)
		return false
	}
	r.env.Ref = ref
	var meta source.BackupMeta
	err = r.timed(PhaseDescribe, func() error {
		var err error
		meta, err = r.opts.Source.Describe(ctx, ref)
		return err
	})
	if meta.Label != "" {
		r.env.Meta, r.res.Meta = &meta, &meta
		r.opts.Progress.Backup(&meta, r.opts.Target)
	}

	r.loadFingerprint(ref.Label)
	if err != nil {
		r.noteSelectError(err)
		return false
	}
	return true
}

func (r *runner) noteSelectError(err error) {
	r.env.SelectErr = err
	if _, isFailure := source.AsFailure(err); !isFailure {
		r.res.InfraErr = errors.Join(r.res.InfraErr, fmt.Errorf("read backup metadata: %w", err))
	}
	r.log.Error("backup selection failed", "error", err.Error())
}

func (r *runner) loadFingerprint(label string) {
	if r.cfg.Fingerprint == nil {
		return
	}
	snap, exact, err := fingerprint.Load(r.cfg.Fingerprint.Dir, r.cfg.Drill.Name, label)
	r.env.Fingerprint, r.env.FingerprintExact, r.env.FingerprintErr = snap, exact, err
	if err != nil {
		r.log.Error("fingerprint not available", "error", err.Error())
		return
	}
	r.res.FingerprintLabel = snap.BackupLabel
	if snap.Bootstrap != "" {
		r.env.Superuser = snap.Bootstrap
	}
	r.env.Database = snap.Database
}

func (r *runner) provision(ctx context.Context) bool {
	err := r.timed(PhaseProvision, func() error {
		inst, err := r.opts.Sandbox.Create(ctx, sandbox.Spec{
			RunID: r.res.RunID, PGMajor: r.res.Meta.PGMajor, Image: r.cfg.ImageFor(r.res.Meta.PGMajor),
			CPUs: r.cfg.Sandbox.CPUs, MemoryBytes: int64(r.cfg.Sandbox.Memory),
		})
		if err != nil {
			return err
		}
		r.inst = inst
		r.env.Inst = inst
		return nil
	})
	if err != nil {
		r.env.ProvisionErr = err
		r.res.InfraErr = errors.Join(r.res.InfraErr, fmt.Errorf("provision the sandbox: %w", err))
		r.log.Error("provisioning failed", "error", err.Error())
		return false
	}
	return true
}

func (r *runner) restoreTarget() source.RestoreTarget {
	return source.RestoreTarget{
		Recovery: r.opts.Target, MemoryBytes: int64(r.cfg.Sandbox.Memory),
		CPUs: r.cfg.Sandbox.CPUs, Superuser: r.env.Superuser,
	}
}

func (r *runner) restore(ctx context.Context) bool {
	r.env.RestoreStarted = true
	start := time.Now()
	err := r.timed(PhaseRestore, func() error {
		out, err := r.opts.Source.Restore(ctx, r.env.Ref, r.restoreTarget(), r.inst)
		if err != nil {
			return err
		}
		if out.Database != "" {
			r.env.Database = out.Database
		}
		return nil
	})
	r.env.RestoreTime = time.Since(start)
	if err != nil {
		r.env.RestoreErr = r.classify(ctx, err)
		r.log.Error("restore failed", "error", err.Error())
		return false
	}
	return true
}

func (r *runner) classify(ctx context.Context, err error) error {
	if _, isFailure := source.AsFailure(err); isFailure {
		return err
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	r.res.InfraErr = errors.Join(r.res.InfraErr, err)
	return err
}

func (r *runner) recover(ctx context.Context) bool {
	rec, ok := r.opts.Source.(source.Recoverer)
	if !ok {
		r.record(PhaseRecover, PhaseSkipped, 0)
		return true
	}
	err := r.timed(PhaseRecover, func() error {
		out, err := rec.Recover(ctx, r.env.Ref, r.restoreTarget(), r.inst)
		r.env.Recovery, r.res.Recovery = &out, &out
		return err
	})
	if err != nil {
		r.env.RecoveryErr = r.classify(ctx, err)
		r.log.Error("recovery failed", "error", err.Error())
		return false
	}
	return true
}

func (r *runner) start(ctx context.Context) bool {
	client := sandbox.Client{Inst: r.inst, Superuser: r.env.Superuser}
	err := r.timed(PhaseStart, func() error {
		if err := client.WaitReady(ctx); err != nil {
			return err
		}
		facts, err := readServerFacts(ctx, client)
		if err != nil {
			return err
		}
		r.env.Server, r.res.Server = facts, facts
		return nil
	})
	if err != nil {
		var exit *sandbox.ServerExitError
		switch {
		case errors.As(err, &exit):
			r.env.ServerErr = exit
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			r.env.ServerErr = fmt.Errorf("it did not accept connections within restore_timeout (%s)", r.cfg.Drill.RestoreTimeout.D())
		default:
			r.env.ServerErr = err
			r.res.InfraErr = errors.Join(r.res.InfraErr, err)
		}
		r.log.Error("server did not start", "error", err.Error())
		return false
	}
	catalog := sandbox.Client{Inst: r.inst, Superuser: r.env.Superuser, Options: "-c search_path=pg_catalog"}
	user := sandbox.Client{Inst: r.inst, Superuser: r.env.Superuser, Options: "-c search_path=public"}
	r.env.Catalog, r.env.User = catalog, user
	r.env.Exec = func(ctx context.Context, argv []string) (sandbox.ExecResult, error) {
		return r.inst.Exec(ctx, argv, nil)
	}
	return true
}

func readServerFacts(ctx context.Context, c sandbox.Client) (*checks.ServerFacts, error) {
	rows, err := c.Query(ctx, sandbox.MaintenanceDB, `SELECT current_setting('server_version'), current_setting('server_version_num'),
	  pg_is_in_recovery()::text, coalesce(pg_last_xact_replay_timestamp()::timestamptz AT TIME ZONE 'UTC', NULL)::text, coalesce(pg_last_wal_replay_lsn()::text, '')`)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 || len(rows[0]) != 5 {
		return nil, errors.New("read server state: unexpected result shape")
	}
	row := rows[0]
	num, err := strconv.Atoi(row[1])
	if err != nil {
		return nil, fmt.Errorf("read server version: %w", err)
	}
	facts := &checks.ServerFacts{
		Version: strings.Fields(row[0])[0], VersionNum: num, Major: num / 10000,
		InRecovery: row[2] == "true", ReplayLSN: row[4],
	}
	if row[3] != "" {
		facts.ReplayTime, err = time.Parse("2006-01-02 15:04:05.999999", row[3])
		if err != nil {
			return nil, fmt.Errorf("read replay time: %w", err)
		}
	}
	return facts, nil
}

func (r *runner) runChecks(ctx context.Context) {
	r.env.Now = time.Now().UTC()
	var results []checks.CheckResult

	limit := r.cfg.Drill.RestoreTimeout.D() + r.cfg.Checks.Amcheck.TimeBudget.D()
	cctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	_ = r.timed(PhaseChecks, func() error {
		results = checks.RunAll(cctx, r.opts.Checks, r.env)
		return nil
	})
	r.res.Checks = results
	for _, c := range results {
		r.opts.Progress.Check(c)
		r.log.Info("check finished", "check", c.ID, "status", c.Status, "seconds", c.Seconds)
	}
	r.res.Verdict = Decide(results, r.res.InfraErr)
}

func Decide(results []checks.CheckResult, infra error) Verdict {
	if infra != nil {
		return VerdictFail
	}
	required := map[string]bool{"restore.completes": false, "server.starts": false}
	verdict := VerdictPass
	for _, c := range results {
		switch c.Status {
		case checks.Fail:
			return VerdictFail
		case checks.Warn:
			verdict = VerdictWarn
		case checks.Pass:
			if _, ok := required[c.ID]; ok {
				required[c.ID] = true
			}
		}
	}
	for _, ok := range required {
		if !ok {
			return VerdictFail
		}
	}
	return verdict
}

func (r *runner) teardown(ctx context.Context) {
	if r.inst == nil {
		r.record(PhaseTeardown, PhaseSkipped, 0)
		return
	}
	id := r.inst.ID()
	if r.opts.KeepSandboxOnFail && r.res.Verdict == VerdictFail {
		if r.opts.Keep != nil {
			if err := r.opts.Keep(context.WithoutCancel(ctx), r.res.RunID, id); err != nil {
				r.log.Error("could not mark the sandbox as kept", "error", err.Error())
			}
		}
		r.log.Info("sandbox kept for inspection", "sandbox", id)
		r.record(PhaseTeardown, PhaseSkipped, 0)
		return
	}
	start := time.Now()
	err := r.opts.Sandbox.Destroy(ctx, id)
	status := PhaseOK
	if err != nil {
		status = PhaseFailed
		r.res.TeardownErr = err
		r.log.Error("teardown failed; pol gc will retry", "sandbox", id, "error", err.Error())
	}
	r.record(PhaseTeardown, status, time.Since(start))
}

type Discard struct{}

func (Discard) Begin(string) {}

func (Discard) Backup(*source.BackupMeta, source.RecoveryTarget) {}

func (Discard) Phase(PhaseTiming) {}

func (Discard) Check(checks.CheckResult) {}
