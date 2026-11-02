package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/drill"
	"github.com/almera-vs/proof-of-life/internal/evidence"
	"github.com/almera-vs/proof-of-life/internal/fingerprint"
	"github.com/almera-vs/proof-of-life/internal/sandbox/docker"
	"github.com/almera-vs/proof-of-life/internal/source"
)

func cmdValidate(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("validate", stderr)
	path := fs.String("c", "", "configuration file")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	v := &validation{w: stdout}
	v.ok("configuration " + *path)
	validateSecrets(cfg, v)
	validateFiles(cfg, v)
	validateFingerprint(ctx, cfg, v)
	validateBackup(ctx, cfg, v)
	switch {
	case v.config > 0:
		return &exitError{code: exitConfig, err: errSilent}
	case v.infra > 0:
		return &exitError{code: exitInfra, err: errSilent}
	}
	fmt.Fprintln(stdout, "Ready. No restore was performed.")
	return nil
}

type validation struct {
	w      io.Writer
	config int
	infra  int
}

func (v *validation) ok(msg string)   { fmt.Fprintf(v.w, "ok      %s\n", msg) }
func (v *validation) note(msg string) { fmt.Fprintf(v.w, "note    %s\n", msg) }
func (v *validation) badConfig(msg string) {
	v.config++
	fmt.Fprintf(v.w, "FAIL    %s\n", msg)
}
func (v *validation) badInfra(msg string) {
	v.infra++
	fmt.Fprintf(v.w, "FAIL    %s\n", msg)
}

func validateSecrets(cfg *config.Config, v *validation) {
	check := func(field string, ref *config.SecretRef) {
		if ref == nil {
			return
		}
		if _, err := ref.Resolve(); err != nil {
			v.badConfig(field + ": " + err.Error())
			return
		}
		v.ok("secret " + field)
	}
	check("source.cipher_pass", cfg.Source.CipherPass)
	check("source.repo.credentials.access_key", cfg.Source.Repo.Credentials.AccessKey)
	check("source.repo.credentials.secret_key", cfg.Source.Repo.Credentials.SecretKey)
	if cfg.Fingerprint != nil {
		check("fingerprint.dsn", &cfg.Fingerprint.DSN)
		if cfg.Fingerprint.Heartbeat.Enabled {
			check("fingerprint.heartbeat.dsn", cfg.Fingerprint.Heartbeat.DSN)
		}
	}
	if cfg.Notify.Slack != nil {
		check("notify.slack.webhook", &cfg.Notify.Slack.Webhook)
	}
	if cfg.Notify.Webhook != nil {
		check("notify.webhook.url", &cfg.Notify.Webhook.URL)
		if u, err := cfg.Notify.Webhook.URL.Resolve(); err == nil && strings.HasPrefix(strings.ToLower(u.Reveal()), "http://") {
			v.note("notify.webhook.url uses http://, so results travel unencrypted")
		}
	}
	if cfg.Source.Repo.VerifyTLS != nil && !*cfg.Source.Repo.VerifyTLS {
		v.note("source.repo.verify_tls is false, so the storage endpoint's identity is not checked")
	}
	if cfg.Notify.SMTP != nil {
		check("notify.smtp.password", cfg.Notify.SMTP.Password)
	}
	if cfg.Source.Repo.Type == "s3" && cfg.Source.Repo.Credentials.FromEnv {
		if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
			v.badConfig("source.repo.credentials: from_env is set but AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY is empty")
		} else {
			v.ok("secret source.repo.credentials")
		}
	}
}

func validateFiles(cfg *config.Config, v *validation) {
	if _, err := evidence.LoadPrivateKey(cfg.Evidence.SignKey); err != nil {
		v.badConfig("evidence.sign_key: " + err.Error())
	} else {
		v.ok("signing key " + cfg.Evidence.SignKey)
	}
	dirs := []string{filepath.Dir(cfg.Evidence.Path), cfg.Report.Dir}
	if cfg.Fingerprint != nil {
		dirs = append(dirs, cfg.Fingerprint.Dir)
	}
	for _, dir := range dirs {
		if err := writable(dir); err != nil {
			v.badInfra(dir + " is not writable: " + err.Error())
		} else {
			v.ok("writable " + dir)
		}
	}
}

func validateFingerprint(ctx context.Context, cfg *config.Config, v *validation) {
	if cfg.Fingerprint == nil {
		v.note("no fingerprint section; schema and data checks will not run")
		return
	}
	dsn, err := cfg.Fingerprint.DSN.Resolve()
	if err != nil {
		return
	}
	conn, err := fingerprint.Connect(ctx, dsn.Reveal(), true)
	if err != nil {
		v.badInfra(err.Error())
		return
	}
	defer conn.Close(context.WithoutCancel(ctx))
	v.ok("fingerprint database " + conn.Database())
	if note := fingerprint.TLSNote(dsn.Reveal()); note != "" {
		v.note(note)
	}
	warnings, err := conn.RoleWarnings(ctx)
	if err != nil {
		v.badInfra("fingerprint role: " + err.Error())
		return
	}
	for _, w := range warnings {
		v.note(w)
	}
	user := conn.WithSearchPath("public")
	for _, t := range cfg.Fingerprint.ExactCountTables {
		if _, err := user.Query(ctx, "", "SELECT 1 FROM "+fingerprint.QuoteTable(t)+" LIMIT 0"); err != nil {
			v.badInfra("fingerprint.exact_count_tables: " + t + " cannot be read by this role")
		} else {
			v.ok("readable " + t)
		}
	}
}

func validateBackup(ctx context.Context, cfg *config.Config, v *validation) {
	sb, err := docker.New(cfg.Sandbox.RestoreNetwork)
	if err != nil {
		v.badInfra("docker: " + err.Error())
		return
	}
	if err := sb.Ping(ctx); err != nil {
		v.badInfra("docker: the daemon does not answer: " + err.Error())
		return
	}
	v.ok("docker daemon")
	runID, err := drill.NewRunID()
	if err != nil {
		v.badInfra(err.Error())
		return
	}
	src, err := newSource(cfg, sb, runID)
	if err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			v.badConfig(ee.err.Error())
		}
		return
	}
	ref, err := src.Latest(ctx)
	if err != nil {
		reportSourceProblem(v, err)
		return
	}
	meta, err := src.Describe(ctx, ref)
	if err != nil {
		reportSourceProblem(v, err)
		return
	}
	v.ok(fmt.Sprintf("backup %s · %s · PostgreSQL %d", meta.Label, meta.Tool, meta.PGMajor))
	image := cfg.ImageFor(meta.PGMajor)
	if err := sb.EnsureImage(ctx, image, nil); err != nil {
		v.badInfra("sandbox image: " + err.Error())
		return
	}
	v.ok("sandbox image " + image)
}

func reportSourceProblem(v *validation, err error) {
	if f, ok := source.AsFailure(err); ok {
		v.badInfra("backup: " + f.Reason)
		return
	}
	v.badInfra("backup source: " + err.Error())
}

func writable(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".pol-validate-*")
	if err != nil {
		return err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(name)
}
