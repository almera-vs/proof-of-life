package pgdump

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/sandbox"
	"github.com/almera-vs/proof-of-life/internal/source"
)

type Source struct {
	pattern string
	store   store
	found   map[string]entry
}

func New(cfg *config.Config) (*Source, error) {
	st, err := newStore(cfg.Source.Repo)
	if err != nil {
		return nil, err
	}
	return &Source{pattern: cfg.Source.Pattern, store: st, found: map[string]entry{}}, nil
}

func (s *Source) Latest(ctx context.Context) (source.BackupRef, error) {
	entries, err := s.store.list(ctx)
	if err != nil {
		return source.BackupRef{}, fmt.Errorf("list pg_dump archives: %w", err)
	}
	e, ok := newest(entries, s.pattern)
	if !ok {
		return source.BackupRef{}, source.Failf(source.FailBackup, "No pg_dump archive was found at the configured location.")
	}
	s.found[e.name] = e
	return source.BackupRef{Label: e.name}, nil
}

func (s *Source) Describe(ctx context.Context, ref source.BackupRef) (source.BackupMeta, error) {
	e, ok := s.found[ref.Label]
	if !ok {
		return source.BackupMeta{}, fmt.Errorf("unknown archive %q", ref.Label)
	}
	meta := source.BackupMeta{
		Label: e.name, Kind: "logical", Tool: "pg_dump", SizeBytes: e.size, RepoBytes: e.size,
		StopTime: e.modTime, StartTime: e.modTime,
	}
	f, err := s.store.head(ctx, e)
	if err != nil {
		return meta, fmt.Errorf("open archive header: %w", err)
	}
	defer f.Close()
	h, err := ReadHeader(f)
	if err != nil {
		if errors.Is(err, ErrNotArchive) || !isConnectivity(err) {
			return meta, source.Failf(source.FailBackup, fmt.Sprintf("%s (%d bytes) is not a readable pg_dump archive: %v.", e.name, e.size, err))
		}
		return meta, source.Failf(source.FailBackup, fmt.Sprintf("%s cannot be used: %v.", e.name, err))
	}
	meta.Format, meta.Database = h.Format, h.Database
	meta.ToolVersion, meta.ServerVersion = h.ToolVer, h.ServerVer
	meta.PGMajor, meta.ToolMajor = h.ServerMajor, h.ToolMajor

	if h.Created.Before(meta.StopTime) {
		meta.StopTime, meta.StartTime = h.Created, h.Created
	}
	return meta, nil
}

func archivePath(ref source.BackupRef) string {
	return sandbox.ArchiveDir + "/" + ref.Label
}

func (s *Source) Restore(ctx context.Context, ref source.BackupRef, target source.RestoreTarget, inst sandbox.Instance) (source.RestoreResult, error) {
	e, ok := s.found[ref.Label]
	if !ok {
		return source.RestoreResult{}, fmt.Errorf("unknown archive %q", ref.Label)
	}
	if err := s.copyIn(ctx, e, inst); err != nil {
		return source.RestoreResult{}, err
	}
	if err := initCluster(ctx, inst, target); err != nil {
		return source.RestoreResult{}, err
	}
	if err := inst.StartServer(ctx, []string{"-D", sandbox.PGData}); err != nil {
		return source.RestoreResult{}, err
	}
	client := sandbox.Client{Inst: inst, Superuser: "postgres"}
	if err := client.WaitReady(ctx); err != nil {
		return source.RestoreResult{}, fmt.Errorf("start the empty cluster: %w", err)
	}
	database, err := pgRestore(ctx, ref, inst, target)
	if err != nil {
		return source.RestoreResult{}, err
	}
	return source.RestoreResult{Database: database}, nil
}

func (s *Source) copyIn(ctx context.Context, e entry, inst sandbox.Instance) error {
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		dirHeader := &tar.Header{Typeflag: tar.TypeDir, Name: "pol-archive/", Mode: 0o700, Uid: 999, Gid: 999}
		err := tw.WriteHeader(dirHeader)
		if err == nil {
			err = s.store.writeTar(ctx, e, "pol-archive/"+e.name, tw)
		}
		if err == nil {
			err = tw.Close()
		}
		_ = pw.CloseWithError(err)
	}()
	if err := inst.CopyIn(ctx, sandbox.DataMount, pr); err != nil {
		return fmt.Errorf("copy the archive into the sandbox: %w", err)
	}
	return nil
}

func initCluster(ctx context.Context, inst sandbox.Instance, target source.RestoreTarget) error {
	res, err := inst.RunJob(ctx, sandbox.Job{Cmd: []string{
		"sh", "-c", `initdb -D "$1" -U postgres --auth-local=trust --auth-host=reject -E UTF8 --locale=C.UTF-8 >/dev/null && printf '%s' "$2" > "$1/postgresql.auto.conf"`,
		"--", sandbox.PGData, sandbox.ServerConfig(target.MemoryBytes, ""),
	}})
	if err != nil {
		return fmt.Errorf("initialise the sandbox cluster: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("initialise the sandbox cluster: initdb: %s", sandbox.FirstError(res.Stderr))
	}
	return nil
}

func pgRestore(ctx context.Context, ref source.BackupRef, inst sandbox.Instance, target source.RestoreTarget) (string, error) {
	listed, err := inst.Exec(ctx, []string{"pg_restore", "-l", archivePath(ref)}, nil)
	if err != nil {
		return "", fmt.Errorf("read the archive table of contents: %w", err)
	}
	if listed.ExitCode != 0 {
		return "", source.Failf(source.FailRestore, "pg_restore could not read the archive: "+sandbox.FirstError(listed.Stderr)+".")
	}
	database := dbNameFromTOC(listed.Stdout)

	if database == "postgres" {
		dropped, err := inst.Exec(ctx, []string{"psql", "-X", "-h", sandbox.SocketDir, "-U", "postgres", "-d", sandbox.MaintenanceDB, "-c", "DROP DATABASE postgres"}, nil)
		if err != nil {
			return "", fmt.Errorf("prepare the sandbox cluster: %w", err)
		}
		if dropped.ExitCode != 0 {
			return "", fmt.Errorf("prepare the sandbox cluster: %s", sandbox.FirstError(dropped.Stderr))
		}
	}
	argv := []string{"pg_restore", "-h", sandbox.SocketDir, "-U", "postgres"}
	if database == sandbox.MaintenanceDB {
		argv = append(argv, "-d", database)
	} else {
		argv = append(argv, "-d", sandbox.MaintenanceDB, "--create")
	}
	argv = append(argv, "--no-owner", "--no-privileges", "--no-tablespaces", "--exit-on-error",
		"-j", strconv.Itoa(max(int(target.CPUs), 1)), archivePath(ref))
	res, err := inst.Exec(ctx, argv, nil)
	if err != nil {
		return "", fmt.Errorf("run pg_restore: %w", err)
	}
	if res.ExitCode != 0 {
		return "", source.Failf(source.FailRestore, "pg_restore stopped with exit code "+strconv.Itoa(res.ExitCode)+": "+restoreError(res.Stderr)+".")
	}
	return database, nil
}

func restoreError(stderr string) string {
	for line := range strings.SplitSeq(stderr, "\n") {
		if strings.Contains(line, "error:") {
			msg := strings.TrimSpace(line)
			if strings.Contains(msg, "COPY failed") {
				_, table, _ := strings.Cut(msg, "COPY failed for table ")
				name, _, _ := strings.Cut(table, ":")
				return "the data for table " + name + " could not be loaded"
			}
			msg = sandbox.RedactValues(msg)
			if strings.Contains(msg, "locale name") {
				return msg + ". The sandbox image does not have this locale; set sandbox.image to one that does"
			}
			if strings.Contains(msg, "extension") {
				return msg + ". The sandbox image does not have this extension; set sandbox.image to one that does"
			}
			return msg
		}
	}
	return sandbox.FirstError(stderr)
}

func dbNameFromTOC(toc string) string {
	for line := range strings.SplitSeq(toc, "\n") {
		if name, ok := strings.CutPrefix(line, ";     dbname: "); ok {
			return strings.TrimSpace(name)
		}
	}
	return ""
}

func (s *Source) Verify(ctx context.Context, ref source.BackupRef, inst sandbox.Instance) (source.VerifyResult, error) {
	res := source.VerifyResult{Tool: "pg_restore -l"}
	if inst == nil {
		return res, errors.New("no sandbox is available to run pg_restore")
	}
	out, err := inst.RunJob(ctx, sandbox.Job{Cmd: []string{
		"sh", "-c", `exec pg_restore -l "$1"`, "--", archivePath(ref),
	}})
	if err != nil {
		return res, fmt.Errorf("run pg_restore -l: %w", err)
	}
	if out.ExitCode != 0 {
		res.Summary = "pg_restore -l failed: " + sandbox.FirstError(out.Stderr)
		return res, nil
	}
	entries := 0
	for line := range strings.SplitSeq(out.Stdout, "\n") {
		if line != "" && !strings.HasPrefix(line, ";") {
			entries++
		}
	}
	res.OK = entries > 0
	res.Summary = fmt.Sprintf("pg_restore -l · %d entries", entries)
	if entries == 0 {
		res.Summary = "pg_restore -l found an empty table of contents"
	}
	return res, nil
}
