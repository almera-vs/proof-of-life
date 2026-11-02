package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/almera-vs/proof-of-life/internal/checks"
	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/drill"
	"github.com/almera-vs/proof-of-life/internal/evidence"
	"github.com/almera-vs/proof-of-life/internal/obs"
	"github.com/almera-vs/proof-of-life/internal/sandbox/docker"
	"github.com/almera-vs/proof-of-life/internal/source"
	"github.com/almera-vs/proof-of-life/internal/source/pgbackrest"
	"github.com/almera-vs/proof-of-life/internal/source/pgdump"
)

func newSource(cfg *config.Config, sb *docker.Sandbox, runID string) (source.BackupSource, error) {
	switch cfg.Source.Type {
	case config.SourcePgBackRest:
		s, err := pgbackrest.New(cfg, sb, runID)
		if err != nil {
			return nil, configErr(err)
		}
		return s, nil
	case config.SourcePgDump:
		s, err := pgdump.New(cfg)
		if err != nil {
			return nil, configErr(err)
		}
		return s, nil
	}
	return nil, configErr(fmt.Errorf("source.type: %q is not supported", cfg.Source.Type))
}

func recoveryTarget(cfg *config.Config, targetTime string) (source.RecoveryTarget, error) {
	if targetTime != "" {
		t, err := time.Parse(time.RFC3339, targetTime)
		if err != nil {
			return source.RecoveryTarget{}, configErr(fmt.Errorf("--target-time: must be RFC 3339, for example 2026-11-01T02:00:00Z"))
		}
		if cfg.Source.Type == config.SourcePgDump {
			return source.RecoveryTarget{}, configErr(errors.New("--target-time: point-in-time recovery needs source.type pgbackrest"))
		}
		return source.RecoveryTarget{Time: t.UTC()}, nil
	}
	t := cfg.Recovery.Target
	out := source.RecoveryTarget{Latest: t.Latest, LSN: t.LSN}
	if t.Time != "" {
		parsed, err := time.Parse(time.RFC3339, t.Time)
		if err != nil {
			return out, configErr(fmt.Errorf("recovery.target.time: %w", err))
		}
		out.Time = parsed.UTC()
	}
	return out, nil
}

func cmdRun(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("run", stderr)
	path := fs.String("c", "", "configuration file")
	targetTime := fs.String("target-time", "", "recover to this RFC 3339 time instead of the configured target")
	keep := fs.Bool("keep-sandbox-on-fail", false, "leave the sandbox in place when the drill fails")
	strict := fs.Bool("strict", false, "exit 2 when the drill passes with warnings")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	target, err := recoveryTarget(cfg, *targetTime)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sb, err := docker.New(cfg.Sandbox.RestoreNetwork)
	if err != nil {
		return infraErr(err)
	}
	runID, err := drill.NewRunID()
	if err != nil {
		return infraErr(err)
	}
	src, err := newSource(cfg, sb, runID)
	if err != nil {
		return err
	}
	key, err := evidence.LoadPrivateKey(cfg.Evidence.SignKey)
	if err != nil {
		return configErr(fmt.Errorf("evidence.sign_key: %w", err))
	}
	progress := newTerminal(stdout, cfg.Drill.Name)
	finish := &finisher{cfg: cfg, key: key}
	res := drill.Run(ctx, runID, drill.Options{
		Config: cfg, Source: src, Sandbox: sb, Checks: checks.All(),
		Logger: obs.NewLogger(stderr), Progress: progress, Target: target,
		KeepSandboxOnFail: *keep, Keep: sb.Keep, AfterChecks: finish.run,
	})
	code := exitCode(res, *strict)
	progress.Finish(cfg, res, finish, code)
	if code != exitPass {
		return &exitError{code: code, err: errSilent}
	}
	return nil
}

func exitCode(res *drill.Result, strict bool) int {
	switch {
	case res.InfraErr != nil:
		return exitInfra
	case res.Verdict == drill.VerdictFail:
		return exitFail
	case res.PostErr != nil || res.TeardownErr != nil:
		return exitInfra
	case res.Verdict == drill.VerdictWarn && strict:
		return exitWarn
	}
	return exitPass
}

func cmdGC(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("gc", stderr)
	all := fs.Bool("all", false, "also remove kept sandboxes and those of other hosts")
	dry := fs.Bool("dry-run", false, "list what would be removed")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	sb, err := docker.New("")
	if err != nil {
		return infraErr(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, err := sb.Collect(ctx, docker.GCOptions{IncludeKept: *all, DryRun: *dry})
	if err != nil && len(res.Runs) == 0 {
		return infraErr(err)
	}
	verb := "removed"
	if *dry {
		verb = "would remove"
	}
	fmt.Fprintf(stdout, "%s %d containers and %d volumes from %d runs\n", verb, res.Containers, res.Volumes, len(res.Runs))
	for _, s := range res.Skipped {
		fmt.Fprintf(stdout, "left in place: %s\n", s)
	}
	if err != nil {
		return infraErr(err)
	}
	return nil
}

type terminal struct {
	w     io.Writer
	color bool
	drill string
	head  bool

	selecting time.Duration
	selectBad bool
	selectOut bool
}

func newTerminal(w io.Writer, drillName string) *terminal {
	color := false
	if f, ok := w.(*os.File); ok {
		if st, err := f.Stat(); err == nil {
			color = st.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == "" && enableColor(f)
		}
	}
	return &terminal{w: w, color: color, drill: drillName}
}

func (t *terminal) paint(code, s string) string {
	if !t.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (t *terminal) dim(s string) string { return t.paint("38;2;140;143;138", s) }

func (t *terminal) Begin(runID string) {
	fmt.Fprintf(t.w, "Proof of Life %s %s %s\n", obs.Version, t.dim("· run"), runID)
}

func (t *terminal) Backup(m *source.BackupMeta, target source.RecoveryTarget) {
	parts := []string{m.Label, m.Tool}
	if m.ToolVersion != "" {
		parts[1] += " " + firstField(m.ToolVersion)
	}
	if m.ServerVersion != "" {
		parts = append(parts, "PostgreSQL "+firstField(m.ServerVersion))
	} else if m.PGMajor != 0 {
		parts = append(parts, fmt.Sprintf("PostgreSQL %d", m.PGMajor))
	}
	if m.SizeBytes > 0 {
		parts = append(parts, obs.FormatBytes(m.SizeBytes))
	}
	fmt.Fprintln(t.w, t.dim("backup  "+strings.Join(parts, " · ")))
	fmt.Fprintln(t.w, t.dim("target  "+targetText(target)))
	fmt.Fprintln(t.w)
	t.flushSelect()
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return s
}

func (t *terminal) flushSelect() {
	if t.selectOut || t.selecting == 0 && !t.selectBad {
		return
	}
	t.selectOut = true
	status := drill.PhaseOK
	if t.selectBad {
		status = drill.PhaseFailed
	}
	t.line("select backup", status, t.selecting)
}

func (t *terminal) line(label string, status drill.PhaseStatus, d time.Duration) {
	mark := t.paint("38;2;127;196;160", "✓")
	if status == drill.PhaseFailed {
		mark = t.paint("38;2;240;128;112", "✗")
	}
	fmt.Fprintf(t.w, "%s %-24s %s\n", mark, label, t.dim(obs.FormatDuration(d)))
}

func targetText(target source.RecoveryTarget) string {
	switch {
	case !target.Time.IsZero():
		return target.Time.Format(time.RFC3339)
	case target.LSN != "":
		return target.LSN
	}
	return "latest"
}

var phaseLabels = map[string]string{
	drill.PhaseImages:    "prepare images",
	drill.PhaseProvision: "provision sandbox", drill.PhaseRestore: "restore",
	drill.PhaseRecover: "recover to target", drill.PhaseStart: "start & promote",
}

func (t *terminal) Phase(p drill.PhaseTiming) {
	d := time.Duration(p.Seconds * float64(time.Second))
	if p.Name == drill.PhaseSelect || p.Name == drill.PhaseDescribe {
		t.selecting += d
		t.selectBad = t.selectBad || p.Status == drill.PhaseFailed
		return
	}
	label, shown := phaseLabels[p.Name]
	if !shown || p.Status == drill.PhaseSkipped {
		return
	}
	if p.Name == drill.PhaseImages && d < time.Second && p.Status == drill.PhaseOK {
		return
	}
	t.line(label, p.Status, d)
}

func (t *terminal) Check(c checks.CheckResult) {
	t.flushSelect()
	if !t.head {
		fmt.Fprintln(t.w)
		t.head = true
	}
	word := map[checks.Status]string{
		checks.Pass:    t.paint("38;2;127;196;160", "pass"),
		checks.Fail:    t.paint("38;2;240;128;112", "FAIL"),
		checks.Warn:    t.paint("38;2;227;207;63", "warn"),
		checks.Skipped: t.dim("skip"),
	}[c.Status]
	fmt.Fprintf(t.w, "%s %-26s %s\n", word, c.ID, t.dim(c.Observed))
}

func (t *terminal) Finish(cfg *config.Config, res *drill.Result, f *finisher, code int) {
	var problems []checks.CheckResult
	counted, passed := 0, 0
	for _, c := range res.Checks {
		if c.Status != checks.Skipped {
			counted++
		}
		if c.Status == checks.Pass {
			passed++
		}
		if c.Status == checks.Fail || c.Status == checks.Warn {
			problems = append(problems, c)
		}
	}
	fmt.Fprintln(t.w)
	if f.written {
		fmt.Fprintf(t.w, "%s  #%d signed · %s\n", t.dim("evidence"), f.seq, cfg.Evidence.Path)
	}
	if f.reportAt != "" {
		fmt.Fprintf(t.w, "%s    %s\n", t.dim("report"), f.reportAt)
	}
	if f.written || f.reportAt != "" {
		fmt.Fprintln(t.w)
	}
	for _, c := range problems {
		fmt.Fprintf(t.w, "%s\n  %s\n", c.ID, c.Reason)
	}
	if res.InfraErr != nil {
		fmt.Fprintf(t.w, "infrastructure\n  %s\n", res.InfraErr)
	}
	if res.PostErr != nil {
		fmt.Fprintf(t.w, "delivery\n  %s\n", res.PostErr)
	}
	if res.TeardownErr != nil {
		fmt.Fprintf(t.w, "teardown\n  The sandbox could not be removed. Run pol gc. %s\n", res.TeardownErr)
	}
	if len(problems) > 0 || res.InfraErr != nil || res.PostErr != nil || res.TeardownErr != nil {
		fmt.Fprintln(t.w)
	}
	badge := map[drill.Verdict]string{
		drill.VerdictPass: t.paint("48;2;227;207;63;38;2;18;19;21", " RESTORABLE "),
		drill.VerdictWarn: t.paint("48;2;227;207;63;38;2;18;19;21", " RESTORABLE WITH WARNINGS "),
		drill.VerdictFail: t.paint("48;2;180;35;24;38;2;255;255;255", " NOT RESTORABLE "),
	}[res.Verdict]
	if res.InfraErr != nil {
		badge = t.paint("48;2;180;35;24;38;2;255;255;255", " NOT PROVEN ")
	}
	rto := "RTO not reached"
	if res.RTOReached {
		rto = "RTO " + obs.FormatDuration(res.RTO)
	}
	fmt.Fprintf(t.w, "%s %d/%d checks · %s of %s · exit %d\n", badge, passed, counted, rto, obs.FormatShort(cfg.Drill.RTOTarget.D()), code)
}
