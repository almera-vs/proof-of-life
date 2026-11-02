package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/drill"
	"github.com/almera-vs/proof-of-life/internal/fingerprint"
	"github.com/almera-vs/proof-of-life/internal/sandbox/docker"
	"github.com/almera-vs/proof-of-life/internal/source"
)

func cmdFingerprint(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return configErr(errors.New("fingerprint: expected capture or heartbeat"))
	}
	switch args[0] {
	case "capture":
		return cmdFingerprintCapture(args[1:], stdout, stderr)
	case "heartbeat":
		return cmdFingerprintHeartbeat(args[1:], stdout, stderr)
	}
	return configErr(fmt.Errorf("fingerprint: unknown subcommand %q", args[0]))
}

func cmdFingerprintCapture(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("fingerprint capture", stderr)
	path := fs.String("c", "", "configuration file")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	if cfg.Fingerprint == nil {
		return configErr(errors.New("fingerprint: this configuration has no fingerprint section"))
	}
	dsn, err := cfg.Fingerprint.DSN.Resolve()
	if err != nil {
		return configErr(fmt.Errorf("fingerprint.dsn: %w", err))
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
	ref, err := src.Latest(ctx)
	if err != nil {
		return infraErr(fmt.Errorf("find the backup to link this fingerprint to: %w", err))
	}
	meta, err := src.Describe(ctx, ref)
	if err != nil {
		return infraErr(fmt.Errorf("describe the backup to link this fingerprint to: %w", err))
	}
	conn, err := fingerprint.Connect(ctx, dsn.Reveal(), true)
	if err != nil {
		return infraErr(err)
	}
	defer conn.Close(context.WithoutCancel(ctx))

	warnings, err := conn.RoleWarnings(ctx)
	if err != nil {
		return infraErr(err)
	}
	for _, w := range warnings {
		fmt.Fprintf(stderr, "note: %s\n", w)
	}
	if note := fingerprint.TLSNote(dsn.Reveal()); note != "" {
		fmt.Fprintf(stderr, "note: %s\n", note)
	}
	snap, err := fingerprint.Capture(ctx, conn, captureInput(cfg, meta))
	if err != nil {
		return infraErr(err)
	}
	file, err := fingerprint.Save(cfg.Fingerprint.Dir, snap)
	if err != nil {
		return infraErr(err)
	}
	fmt.Fprintf(stdout, "fingerprint captured · backup %s · PostgreSQL %s · %d objects · %d tables · %s\n",
		snap.BackupLabel, snap.ServerVersion, len(snap.Objects), len(snap.Tables), file)
	return nil
}

func captureInput(cfg *config.Config, meta source.BackupMeta) fingerprint.CaptureInput {
	assertions := map[string]string{}
	for _, a := range cfg.Assertions {
		if a.Expect.EqualsFingerprint {
			assertions[a.Name] = a.SQL
		}
	}
	return fingerprint.CaptureInput{
		Drill: cfg.Drill.Name, Label: meta.Label, StopLSN: meta.StopLSN, StopTime: meta.StopTime,
		ExactTables: cfg.Fingerprint.ExactCountTables, Assertions: assertions,
	}
}

func cmdFingerprintHeartbeat(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("fingerprint heartbeat", stderr)
	path := fs.String("c", "", "configuration file")
	once := fs.Bool("once", false, "write one heartbeat and exit")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	if cfg.Fingerprint == nil || !cfg.Fingerprint.Heartbeat.Enabled {
		return configErr(errors.New("fingerprint.heartbeat.enabled: the heartbeat is off; it is the only feature that writes to production, so it must be enabled explicitly"))
	}
	if cfg.Fingerprint.Heartbeat.DSN == nil {
		return configErr(errors.New("fingerprint.heartbeat.dsn: required to write heartbeats"))
	}
	dsn, err := cfg.Fingerprint.Heartbeat.DSN.Resolve()
	if err != nil {
		return configErr(fmt.Errorf("fingerprint.heartbeat.dsn: %w", err))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(stdout, "writing heartbeats every %s\n", cfg.Fingerprint.Heartbeat.Interval.D())
	if err := fingerprint.RunHeartbeat(ctx, dsn.Reveal(), cfg.Fingerprint.Heartbeat.Interval.D(), *once); err != nil {
		return infraErr(err)
	}
	return nil
}
