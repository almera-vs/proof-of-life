package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/drill"
	"github.com/almera-vs/proof-of-life/internal/evidence"
	"github.com/almera-vs/proof-of-life/internal/notify"
	"github.com/almera-vs/proof-of-life/internal/obs"
	"github.com/almera-vs/proof-of-life/internal/report"
)

func cmdEvidence(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return configErr(errors.New("evidence: expected keygen or verify"))
	}
	switch args[0] {
	case "keygen":
		return cmdKeygen(args[1:], stdout, stderr)
	case "verify":
		return cmdVerify(args[1:], stdout, stderr)
	}
	return configErr(fmt.Errorf("evidence: unknown subcommand %q", args[0]))
}

func cmdKeygen(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("evidence keygen", stderr)
	out := fs.String("out", "", "file for the private key; the public key goes to <out>.pub")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return configErr(errors.New("--out: required"))
	}
	pub, err := evidence.GenerateKey(*out)
	if err != nil {
		return configErr(err)
	}
	fmt.Fprintf(stdout, "Wrote private key %s and public key %s. Keep the private key on this host, and give auditors the public key.\n", *out, pub)
	return nil
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

var _ flag.Value = (*stringList)(nil)

func cmdVerify(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("evidence verify", stderr)
	log := fs.String("log", "", "evidence log")
	var pubs stringList
	fs.Var(&pubs, "pub", "public key; repeat for logs that span a key rotation")
	headFile := fs.String("head", "", "signed head file (default <log>.head)")
	noHead := fs.Bool("no-head", false, "verify without a head file; removal of the newest records is then not detected")
	minSeq := fs.Uint64("min-seq", 0, "fail if the log ends before this record, for example the number in a report you filed")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *log == "" {
		return configErr(errors.New("--log: required"))
	}
	if len(pubs) == 0 {
		return configErr(errors.New("--pub: required"))
	}
	keys := make([]ed25519.PublicKey, 0, len(pubs))
	for _, p := range pubs {
		k, err := evidence.LoadPublicKey(p)
		if err != nil {
			return configErr(err)
		}
		keys = append(keys, k)
	}
	head := *headFile
	if head == "" {
		head = evidence.HeadPath(*log)
	}
	res, err := evidence.Verify(*log, head, keys, evidence.VerifyOptions{HeadOptional: *noHead, MinSeq: *minSeq})
	if err != nil {
		fmt.Fprintf(stdout, "NOT VERIFIED  %s\n", err)
		return &exitError{code: exitFail, err: errSilent}
	}
	fmt.Fprintf(stdout, "VERIFIED  %d records · chain intact · all signatures valid · last %s\n", res.Records, res.LastHash)
	for _, w := range res.Warnings {
		fmt.Fprintf(stdout, "note      %s\n", w)
	}
	return nil
}

func cmdReport(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "show" {
		return configErr(errors.New("report: expected show <run-id>"))
	}
	args = args[1:]
	runID := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		runID, args = args[0], args[1:]
	}
	fs := newFlags("report show", stderr)
	format := fs.String("format", "json", "json or html")
	path := fs.String("c", "", "configuration file, to find the report directory")
	dir := fs.String("dir", "", "report directory")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if runID == "" && fs.NArg() > 0 {
		runID = fs.Arg(0)
	}
	if runID == "" {
		return configErr(errors.New("report show: a run id is required"))
	}
	reportDir := *dir
	if reportDir == "" && *path != "" {
		cfg, err := loadConfig(*path)
		if err != nil {
			return err
		}
		reportDir = cfg.Report.Dir
	}
	if reportDir == "" {
		reportDir = "/var/lib/pol/reports"
	}
	r, err := report.Load(reportDir, runID)
	if err != nil {
		return configErr(err)
	}
	var out []byte
	switch *format {
	case "json":
		out, err = r.JSON()
	case "html":
		out, err = r.HTML()
	default:
		return configErr(fmt.Errorf("--format: must be json or html, got %q", *format))
	}
	if err != nil {
		return infraErr(err)
	}
	_, err = stdout.Write(out)
	return err
}

type finisher struct {
	cfg      *config.Config
	key      ed25519.PrivateKey
	reportAt string
	seq      uint64
	written  bool
}

func (f *finisher) run(ctx context.Context, res *drill.Result, timed func(string, func() error) error) error {
	var errs []error
	ev := report.Evidence{Log: f.cfg.Evidence.Path}
	if err := timed(drill.PhaseEvidence, func() error {
		w, err := evidence.Append(f.cfg.Evidence.Path, f.key, record(res))
		if err != nil {
			return err
		}
		ev = report.EvidenceFrom(w, f.cfg.Evidence.Path)
		f.seq, f.written = w.Seq, true
		return nil
	}); err != nil {
		ev.Error = err.Error()
		errs = append(errs, fmt.Errorf("write evidence: %w", err))
	}
	var built *report.Report
	if err := timed(drill.PhaseReport, func() error {
		built = report.Build(f.cfg, res, ev)
		path, err := built.Write(f.cfg.Report.Dir)
		f.reportAt = path
		return err
	}); err != nil {
		errs = append(errs, fmt.Errorf("write report: %w", err))
	}
	if built != nil && notify.Wanted(f.cfg.Notify, built.Status) {
		if err := timed(drill.PhaseNotify, func() error {
			return notify.Send(context.WithoutCancel(ctx), f.cfg.Notify, notify.Build(built, f.reportAt))
		}); err != nil {
			errs = append(errs, fmt.Errorf("deliver notification: %w", err))
		}
	}
	if f.cfg.Metrics.Textfile != "" && built != nil {
		if err := obs.WriteTextfile(f.cfg.Metrics.Textfile, obs.Metrics{
			Drill: res.Drill, Status: built.Status, RTOSeconds: built.RTO.Seconds, RTOReached: built.RTO.Reached,
			TargetSeconds: built.RTO.TargetSeconds, BackupAge: built.Backup.AgeSeconds, Finished: time.Now(),
			Passed: built.Counts.Passed, Warned: built.Counts.Warnings, Failed: built.Counts.Failed, Skipped: built.Counts.Skipped,
		}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func record(res *drill.Result) evidence.Record {
	r := evidence.Record{
		RunID: res.RunID, Drill: res.Drill, Verdict: string(res.Verdict),
		Tools: evidence.Tools{Agent: "pol " + obs.Version},
	}
	if res.InfraErr != nil {
		r.Verdict = "not_proven"
	}
	if res.RTOReached {
		r.RTOSeconds = res.RTO.Seconds()
	}
	if m := res.Meta; m != nil {
		r.Backup = evidence.Backup{
			Label: m.Label, Kind: m.Kind, Tool: m.Tool, ToolVersion: m.ToolVersion, PGMajor: m.PGMajor,
			StartLSN: m.StartLSN, StopLSN: m.StopLSN, SizeBytes: m.SizeBytes,
		}
		if !m.StartTime.IsZero() {
			r.Backup.StartTime = m.StartTime.UTC().Format(time.RFC3339)
		}
		if !m.StopTime.IsZero() {
			r.Backup.StopTime = m.StopTime.UTC().Format(time.RFC3339)
		}
		r.Tools.Backup = strings.TrimSpace(m.Tool + " " + m.ToolVersion)
	}
	if res.Server != nil {
		r.Tools.Server = "PostgreSQL " + res.Server.Version
	}
	for _, c := range res.Checks {
		ec := evidence.Check{ID: c.ID, Status: string(c.Status), Severity: string(c.Severity), Observed: c.Observed, Reason: c.Reason, Seconds: c.Seconds}
		for _, ref := range c.Controls {
			ec.Controls = append(ec.Controls, string(ref))
		}
		r.Checks = append(r.Checks, ec)
	}
	for _, p := range res.Phases {
		r.Phases = append(r.Phases, evidence.Phase{Name: p.Name, Status: string(p.Status), Seconds: p.Seconds})
	}
	return r
}
