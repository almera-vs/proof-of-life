package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/obs"
)

const (
	exitPass   = 0
	exitFail   = 1
	exitWarn   = 2
	exitConfig = 3
	exitInfra  = 4
)

const usage = `Proof of Life proves that PostgreSQL backups restore.

Usage:
  pol init [--out drill.yaml]             write a commented example config
  pol validate -c drill.yaml              config, connectivity and permissions dry run, no restore
  pol fingerprint capture -c drill.yaml   record the reference state of production
  pol fingerprint heartbeat -c drill.yaml write PITR heartbeats (opt-in, writes to production)
  pol run -c drill.yaml [--target-time ...] [--keep-sandbox-on-fail] [--strict]
  pol evidence keygen --out key           create an ed25519 signing key
  pol evidence verify --log evidence.jsonl --pub key.pub
  pol report show <run-id> -c drill.yaml [--format json|html]
  pol gc [--all] [--dry-run]              remove orphaned sandboxes and volumes
  pol version

Exit codes: 0 pass, 1 check failure, 2 warnings only (with --strict),
3 configuration or usage error, 4 infrastructure error.
`

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func configErr(err error) error { return &exitError{code: exitConfig, err: err} }
func infraErr(err error) error  { return &exitError{code: exitInfra, err: err} }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitConfig
	}
	commands := map[string]func([]string, io.Writer, io.Writer) error{
		"init":        cmdInit,
		"run":         cmdRun,
		"gc":          cmdGC,
		"fingerprint": cmdFingerprint,
		"evidence":    cmdEvidence,
		"report":      cmdReport,
		"validate":    cmdValidate,
		"version":     cmdVersion,
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, usage)
		return exitPass
	}
	cmd, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return exitConfig
	}
	err := cmd(args[1:], stdout, stderr)
	if err == nil {
		return exitPass
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil && !errors.Is(ee.err, errSilent) {
			fmt.Fprintln(stderr, ee.err)
		}
		return ee.code
	}
	fmt.Fprintln(stderr, err)
	return exitInfra
}

var errSilent = errors.New("silent")

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return &exitError{code: exitPass, err: errSilent}
		}
		return &exitError{code: exitConfig, err: errSilent}
	}
	return nil
}

func loadConfig(path string) (*config.Config, error) {
	if path == "" {
		return nil, configErr(errors.New("-c: a configuration file is required"))
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, configErr(err)
	}
	return cfg, nil
}

func cmdInit(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("init", stderr)
	out := fs.String("out", "drill.yaml", "file to write")
	force := fs.Bool("force", false, "overwrite an existing file")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if *force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(*out, flags, 0o640)
	if err != nil {
		return configErr(fmt.Errorf("write example config: %w", err))
	}
	if _, err := f.Write(config.Example); err != nil {
		_ = f.Close()
		return configErr(fmt.Errorf("write example config: %w", err))
	}
	if err := f.Close(); err != nil {
		return configErr(fmt.Errorf("write example config: %w", err))
	}
	fmt.Fprintf(stdout, "Wrote %s. Edit it, then run: pol validate -c %s\n", *out, *out)
	return nil
}

func cmdVersion(_ []string, stdout, _ io.Writer) error {
	fmt.Fprintf(stdout, "pol %s %s/%s %s\n", obs.Version, runtime.GOOS, runtime.GOARCH, strings.TrimPrefix(runtime.Version(), "go"))
	return nil
}
