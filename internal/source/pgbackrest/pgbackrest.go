package pgbackrest

import (
	"archive/tar"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/sandbox"
	"github.com/almera-vs/proof-of-life/internal/source"
)

const DefaultToolImage = "pol-pgbackrest:0.1.0"

//go:embed tool.Dockerfile
var toolDockerfile []byte

const repoMount = "/pol-repo"

type Source struct {
	cfg    *config.Config
	sb     sandbox.Sandbox
	runID  string
	image  string
	env    []string
	binds  []string
	backup map[string]infoBackup
	tool   string
}

func New(cfg *config.Config, sb sandbox.Sandbox, runID string) (*Source, error) {
	env, binds, err := jobEnv(cfg)
	if err != nil {
		return nil, err
	}
	image := cfg.Source.ToolImage
	if image == "" {
		image = DefaultToolImage
	}
	return &Source{cfg: cfg, sb: sb, runID: runID, image: image, env: env, binds: binds, backup: map[string]infoBackup{}}, nil
}

func jobEnv(cfg *config.Config) (env, binds []string, err error) {
	repo := cfg.Source.Repo
	env = []string{
		"PGBACKREST_STANZA=" + cfg.Source.Stanza,
		"PGBACKREST_PG1_PATH=" + sandbox.PGData,
		"PGBACKREST_LOG_LEVEL_FILE=off",
		"PGBACKREST_LOG_LEVEL_CONSOLE=error",
		"PGBACKREST_LOG_LEVEL_STDERR=off",
		"PGBACKREST_LOCK_PATH=/tmp/pgbackrest",
	}
	switch repo.Type {
	case "posix":
		env = append(env, "PGBACKREST_REPO1_TYPE=posix", "PGBACKREST_REPO1_PATH="+repoMount)
		binds = append(binds, repo.Path+":"+repoMount+":ro")
	case "s3":
		endpoint := repo.Endpoint
		if endpoint == "" {
			endpoint = "s3." + repo.Region + ".amazonaws.com"
		}
		path := repo.Path
		if path == "" {
			path = "/"
		}
		env = append(env,
			"PGBACKREST_REPO1_TYPE=s3",
			"PGBACKREST_REPO1_PATH="+path,
			"PGBACKREST_REPO1_S3_BUCKET="+repo.Bucket,
			"PGBACKREST_REPO1_S3_REGION="+repo.Region,
			"PGBACKREST_REPO1_S3_ENDPOINT="+endpoint,
			"PGBACKREST_REPO1_S3_URI_STYLE="+repo.URIStyle,
		)
		if repo.Port != 0 {
			env = append(env, "PGBACKREST_REPO1_STORAGE_PORT="+strconv.Itoa(repo.Port))
		}
		if repo.VerifyTLS != nil && !*repo.VerifyTLS {
			env = append(env, "PGBACKREST_REPO1_STORAGE_VERIFY_TLS=n")
		}
		creds, err := s3Env(repo.Credentials)
		if err != nil {
			return nil, nil, err
		}
		env = append(env, creds...)
	}
	if cfg.Source.CipherPass != nil {
		pass, err := cfg.Source.CipherPass.Resolve()
		if err != nil {
			return nil, nil, fmt.Errorf("source.cipher_pass: %w", err)
		}
		env = append(env, "PGBACKREST_REPO1_CIPHER_TYPE=aes-256-cbc", "PGBACKREST_REPO1_CIPHER_PASS="+pass.Reveal())
	}
	return env, binds, nil
}

func s3Env(c config.Credentials) ([]string, error) {
	var key, secret, token string
	if c.FromEnv {
		key, secret, token = lookupAWS()
		if key == "" || secret == "" {
			return nil, errors.New("source.repo.credentials: from_env is set but AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY is empty")
		}
	} else {
		k, err := c.AccessKey.Resolve()
		if err != nil {
			return nil, fmt.Errorf("source.repo.credentials.access_key: %w", err)
		}
		s, err := c.SecretKey.Resolve()
		if err != nil {
			return nil, fmt.Errorf("source.repo.credentials.secret_key: %w", err)
		}
		key, secret = k.Reveal(), s.Reveal()
	}
	out := []string{"PGBACKREST_REPO1_S3_KEY=" + key, "PGBACKREST_REPO1_S3_KEY_SECRET=" + secret}
	if token != "" {
		out = append(out, "PGBACKREST_REPO1_S3_TOKEN="+token)
	}
	return out, nil
}

func (s *Source) withToolInstance(ctx context.Context, fn func(sandbox.Instance) error) error {
	inst, err := s.sb.Create(ctx, sandbox.Spec{
		RunID: s.runID, Image: s.image, Dockerfile: toolDockerfile,
		CPUs: s.cfg.Sandbox.CPUs, MemoryBytes: int64(s.cfg.Sandbox.Memory),
	})
	if err != nil {
		return err
	}
	defer func() { _ = s.sb.Destroy(context.WithoutCancel(ctx), inst.ID()) }()
	return fn(inst)
}

func (s *Source) job(cmd ...string) sandbox.Job {
	job := sandbox.Job{Image: s.image, Cmd: cmd, Env: s.env, Network: "restore", Binds: s.binds}
	if gid := s.cfg.Source.Repo.ReadGID; gid != 0 {
		job.Groups = []string{strconv.Itoa(gid)}
	}
	return job
}

func (s *Source) Prepare(ctx context.Context) error {
	if ip, ok := s.sb.(sandbox.ImagePreparer); ok {
		return ip.EnsureImage(ctx, s.image, toolDockerfile)
	}
	return nil
}

type infoStanza struct {
	Name   string       `json:"name"`
	Status infoStatus   `json:"status"`
	Repo   []infoRepo   `json:"repo"`
	Backup []infoBackup `json:"backup"`
	DB     []infoDB     `json:"db"`
}

type infoStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type infoRepo struct {
	Status infoStatus `json:"status"`
}

type infoDB struct {
	ID      int    `json:"id"`
	Version string `json:"version"`
}

type infoBackup struct {
	Label     string `json:"label"`
	Type      string `json:"type"`
	Error     bool   `json:"error"`
	Timestamp struct {
		Start int64 `json:"start"`
		Stop  int64 `json:"stop"`
	} `json:"timestamp"`
	LSN struct {
		Start string `json:"start"`
		Stop  string `json:"stop"`
	} `json:"lsn"`
	Archive struct {
		Start string `json:"start"`
		Stop  string `json:"stop"`
	} `json:"archive"`
	Backrest struct {
		Version string `json:"version"`
	} `json:"backrest"`
	Database struct {
		ID int `json:"id"`
	} `json:"database"`
	Info struct {
		Size       int64 `json:"size"`
		Repository struct {
			Size int64 `json:"size"`
		} `json:"repository"`
	} `json:"info"`
}

func (s *Source) Latest(ctx context.Context) (source.BackupRef, error) {
	st, err := s.readInfo(ctx)
	if err != nil {
		return source.BackupRef{}, err
	}
	if len(st.Backup) == 0 {
		return source.BackupRef{}, source.Failf(source.FailBackup, "The repository for stanza "+s.cfg.Source.Stanza+" holds no backups.")
	}
	last := st.Backup[len(st.Backup)-1]
	s.backup[last.Label] = last
	return source.BackupRef{Label: last.Label}, nil
}

func cleanJSON(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
}

func (s *Source) readInfo(ctx context.Context) (infoStanza, error) {
	var out sandbox.ExecResult
	err := s.withToolInstance(ctx, func(inst sandbox.Instance) error {
		var err error
		if out, err = inst.RunJob(ctx, s.job("sh", "-c", `pgbackrest version; pgbackrest info --output=json`)); err != nil {
			return fmt.Errorf("run pgbackrest info: %w", err)
		}
		return nil
	})
	if err != nil {
		return infoStanza{}, err
	}
	version, body, _ := strings.Cut(out.Stdout, "\n")
	s.tool = strings.TrimPrefix(strings.TrimSpace(version), "pgBackRest ")
	var stanzas []infoStanza
	if err := json.Unmarshal([]byte(cleanJSON(body)), &stanzas); err != nil || len(stanzas) == 0 {
		return infoStanza{}, fmt.Errorf("pgbackrest info gave no usable output: %s", sandbox.FirstError(out.Stdout+out.Stderr))
	}
	st := stanzas[0]
	if st.Status.Code != 0 {
		return st, classifyStatus(st, s.cfg.Source.CipherPass != nil)
	}
	return st, nil
}

func classifyStatus(st infoStanza, encrypted bool) error {
	msg := st.Status.Message
	if len(st.Repo) > 0 && st.Repo[0].Status.Message != "" {
		msg = st.Repo[0].Status.Message
	}
	switch {
	case strings.Contains(msg, "ermission denied"):
		return errors.New("pgBackRest runs as uid 999 and may not read the repository; set source.repo.read_gid to a group that can: " + firstLine(msg))
	case strings.Contains(msg, "FormatError") || strings.Contains(msg, "CryptoError"):
		if encrypted {
			return source.Failf(source.FailBackup, "The repository could not be decrypted. The configured passphrase does not open it, so this backup cannot be restored with the key you hold.")
		}
		return source.Failf(source.FailBackup, "The repository files could not be read. It may be encrypted, while no cipher_pass is configured, or its info files may be damaged.")
	case strings.Contains(msg, "HostConnectError"), strings.Contains(msg, "unable to get address"), strings.Contains(msg, "TLS"), strings.Contains(msg, "HttpError"):
		return fmt.Errorf("the backup repository could not be reached: %s", firstLine(msg))
	case st.Status.Code == 1 || st.Status.Code == 2 || st.Status.Code == 3:
		return source.Failf(source.FailBackup, "The repository for stanza "+st.Name+" holds no usable backups: "+firstLine(st.Status.Message)+".")
	}
	return source.Failf(source.FailBackup, "pgBackRest reported the repository as unusable: "+firstLine(msg)+".")
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return strings.TrimSpace(line)
}

func (s *Source) Describe(ctx context.Context, ref source.BackupRef) (source.BackupMeta, error) {
	b, ok := s.backup[ref.Label]
	if !ok {
		return source.BackupMeta{}, fmt.Errorf("unknown backup %q", ref.Label)
	}
	st, err := s.readInfo(ctx)
	if err != nil {
		return source.BackupMeta{}, err
	}
	meta := source.BackupMeta{
		Label: b.Label, Kind: b.Type, Tool: "pgBackRest", ToolVersion: b.Backrest.Version, RestoreToolVersion: s.tool,
		StartLSN: b.LSN.Start, StopLSN: b.LSN.Stop,
		StartTime: time.Unix(b.Timestamp.Start, 0).UTC(), StopTime: time.Unix(b.Timestamp.Stop, 0).UTC(),
		SizeBytes: b.Info.Size, RepoBytes: b.Info.Repository.Size, PageErrors: b.Error,
		ArchiveStart: b.Archive.Start, ArchiveStop: b.Archive.Stop,
	}
	for _, db := range st.DB {
		if db.ID != b.Database.ID {
			continue
		}
		major, err := strconv.Atoi(db.Version)
		if err != nil {
			return meta, fmt.Errorf("unrecognised PostgreSQL version %q in the repository", db.Version)
		}
		meta.PGMajor = major
		meta.ArchiveID = fmt.Sprintf("%s-%d", db.Version, db.ID)
	}
	if meta.PGMajor == 0 {
		return meta, source.Failf(source.FailBackup, "The repository does not say which PostgreSQL version backup "+b.Label+" belongs to.")
	}
	return meta, nil
}

func (s *Source) Restore(ctx context.Context, ref source.BackupRef, _ source.RestoreTarget, inst sandbox.Instance) (source.RestoreResult, error) {
	cmd := `mkdir -m 700 "$PGBACKREST_PG1_PATH" && exec pgbackrest restore --set="$1" --no-delta --tablespace-map-all=` + sandbox.DataMount + `/pol-tablespaces --process-max="$2"`
	cpus := strconv.Itoa(max(int(s.cfg.Sandbox.CPUs), 1))
	out, err := inst.RunJob(ctx, s.job("sh", "-c", cmd, "--", ref.Label, cpus))
	if err != nil {
		return source.RestoreResult{}, fmt.Errorf("run pgbackrest restore: %w", err)
	}
	if out.ExitCode != 0 {
		return source.RestoreResult{}, source.Failf(source.FailRestore, fmt.Sprintf("pgbackrest restore stopped with exit code %d: %s.", out.ExitCode, toolError(out)))
	}
	return source.RestoreResult{}, nil
}

var logPrefix = regexp.MustCompile(`^\S+ \S+ P\d+\s+(ERROR|WARN|INFO):\s*`)

func toolError(out sandbox.ExecResult) string {
	for _, text := range []string{out.Stderr, out.Stdout} {
		for line := range strings.SplitSeq(text, "\n") {
			if strings.Contains(line, "ERROR") {
				return strings.TrimSpace(logPrefix.ReplaceAllString(line, ""))
			}
		}
	}
	return sandbox.FirstError(out.Stderr + out.Stdout)
}

var leadingDigits = regexp.MustCompile(`^[0-9]+`)

var walSizeLine = regexp.MustCompile(`(?m)^Bytes per WAL segment:\s+(\d+)$`)

func (s *Source) Recover(ctx context.Context, ref source.BackupRef, target source.RestoreTarget, inst sandbox.Instance) (source.RecoveryResult, error) {
	var res source.RecoveryResult
	b, ok := s.backup[ref.Label]
	if !ok {
		return res, fmt.Errorf("unknown backup %q", ref.Label)
	}
	walSize, err := readWALSize(ctx, inst)
	if err != nil {
		return res, err
	}
	archiveID, err := s.archiveID(ctx, b)
	if err != nil {
		return res, err
	}
	p, err := s.planWAL(ctx, inst, archiveID, b.Archive.Start, b.Archive.Stop, walSize)
	if err != nil {
		return res, err
	}
	res.SegmentsNeeded = len(p.Needed) + len(p.Missing)
	res.Missing = p.Missing
	if len(p.Needed) > 0 {
		res.LastSegment = p.Last.name(walSize)
		res.LastSegmentLSN = p.Last.startLSN(walSize)
	}
	failed, err := s.fetchWAL(ctx, inst, append(p.Histories, p.Needed...))
	if err != nil {
		return res, err
	}
	res.Unreadable = failed
	res.SegmentsFetched = len(p.Needed) + len(p.Histories) - len(failed)
	res.SegmentsFetched = max(res.SegmentsFetched-len(p.Histories), 0)
	if err := writeServerFiles(ctx, inst, target); err != nil {
		return res, err
	}
	if err := inst.StartServer(ctx, []string{"-D", sandbox.PGData}); err != nil {
		return res, err
	}
	client := sandbox.Client{Inst: inst, Superuser: target.Superuser}
	if err := client.WaitReady(ctx); err != nil {
		var exit *sandbox.ServerExitError
		if errors.As(err, &exit) {
			res.ServerFatal = exit.Fatal
			res.SegmentsReplayed = countRestored(exit.Logs)
			return res, source.Failf(source.FailRecovery, exit.Error())
		}
		return res, err
	}
	logs, err := inst.ServerLogs(ctx)
	if err != nil {
		return res, err
	}
	res.SegmentsReplayed = countRestored(logs)
	return res, nil
}

func countRestored(logs string) int {
	return strings.Count(logs, "restored log file")
}

func readWALSize(ctx context.Context, inst sandbox.Instance) (int64, error) {
	out, err := inst.RunJob(ctx, sandbox.Job{Cmd: []string{"pg_controldata", sandbox.PGData}})
	if err != nil {
		return 0, fmt.Errorf("run pg_controldata: %w", err)
	}
	if out.ExitCode != 0 {
		return 0, source.Failf(source.FailRestore, "The restored data directory has no readable control file: "+sandbox.FirstError(out.Stderr)+".")
	}
	m := walSizeLine.FindStringSubmatch(out.Stdout)
	if m == nil {
		return 0, errors.New("pg_controldata did not report the WAL segment size")
	}
	size, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || size < 1<<20 || size > 1<<30 || size&(size-1) != 0 {
		return 0, fmt.Errorf("pg_controldata reported an invalid WAL segment size %q", m[1])
	}
	return size, nil
}

func (s *Source) archiveID(ctx context.Context, b infoBackup) (string, error) {
	st, err := s.readInfo(ctx)
	if err != nil {
		return "", err
	}
	for _, db := range st.DB {
		if db.ID == b.Database.ID {
			return fmt.Sprintf("%s-%d", db.Version, db.ID), nil
		}
	}
	return "", errors.New("the repository lists no database for this backup")
}

func (s *Source) planWAL(ctx context.Context, inst sandbox.Instance, archiveID, start, stop string, walSize int64) (plan, error) {
	out, err := inst.RunJob(ctx, s.job("pgbackrest", "repo-ls", "--recurse", "--output=json", "archive/"+s.cfg.Source.Stanza+"/"+archiveID))
	if err != nil {
		return plan{}, fmt.Errorf("list the WAL archive: %w", err)
	}
	if out.ExitCode != 0 {
		return plan{}, fmt.Errorf("list the WAL archive: %s", toolError(out))
	}
	l, err := parseListing([]byte(out.Stdout), walSize)
	if err != nil {
		return plan{}, err
	}
	histories := map[uint32][]switchPoint{}
	for _, tli := range l.histories {
		name := fmt.Sprintf("%08X.history", tli)
		h, err := inst.RunJob(ctx, s.job("sh", "-c", `pgbackrest archive-get "$1" /tmp/h && cat /tmp/h`, "--", name))
		if err != nil {
			return plan{}, fmt.Errorf("read %s: %w", name, err)
		}
		if h.ExitCode != 0 {
			return plan{}, source.Failf(source.FailRecovery, "Timeline history "+name+" could not be read: "+toolError(h)+".")
		}
		if histories[tli], err = parseHistory(h.Stdout); err != nil {
			return plan{}, source.Failf(source.FailRecovery, "Timeline history "+name+" is damaged: "+err.Error()+".")
		}
	}
	p, err := buildPlan(l, start, stop, histories, walSize)
	if err != nil {
		return plan{}, source.Failf(source.FailRecovery, err.Error()+".")
	}
	return p, nil
}

const fetchScript = `mkdir -p "$POL_WAL" && cd "$POL_WAL" && tr ' ' '\n' < "$POL_LIST" | xargs -P "$POL_PAR" -I{} sh -c 'pgbackrest archive-get "{}" "$POL_WAL/{}" || echo "POLFAILED {}"'; exit 0`

func (s *Source) fetchWAL(ctx context.Context, inst sandbox.Instance, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	list := sandbox.DataMount + "/pol-wal.list"
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte(strings.Join(names, " "))
	if err := tw.WriteHeader(&tar.Header{Name: "pol-wal.list", Mode: 0o600, Size: int64(len(body)), Uid: 999, Gid: 999}); err != nil {
		return nil, fmt.Errorf("prepare WAL list: %w", err)
	}
	if _, err := tw.Write(body); err != nil {
		return nil, fmt.Errorf("prepare WAL list: %w", err)
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("prepare WAL list: %w", err)
	}
	if err := inst.CopyIn(ctx, sandbox.DataMount, &buf); err != nil {
		return nil, fmt.Errorf("copy WAL list: %w", err)
	}
	job := s.job("sh", "-c", fetchScript)
	job.Env = append(job.Env[:len(job.Env):len(job.Env)], "POL_WAL="+sandbox.WALDir, "POL_LIST="+list,
		"POL_PAR="+strconv.Itoa(max(int(s.cfg.Sandbox.CPUs), 1)))
	out, err := inst.RunJob(ctx, job)
	if err != nil {
		return nil, fmt.Errorf("fetch WAL: %w", err)
	}
	var failed []string
	for line := range strings.SplitSeq(out.Stdout, "\n") {
		if name, ok := strings.CutPrefix(line, "POLFAILED "); ok {
			failed = append(failed, name)
		}
	}
	return failed, nil
}

func writeServerFiles(ctx context.Context, inst sandbox.Instance, target source.RestoreTarget) error {
	conf := sandbox.ServerConfig(target.MemoryBytes, recoverySettings(target.Recovery))
	out, err := inst.RunJob(ctx, sandbox.Job{Cmd: []string{"sh", "-c",
		`printf '%s' "$1" > "$3/postgresql.conf" && : > "$3/postgresql.auto.conf" && printf '%s' "$2" > "$3/pg_hba.conf" && : > "$3/pg_ident.conf" && touch "$3/recovery.signal"`,
		"--", conf, sandbox.HBAConfig, sandbox.PGData,
	}})
	if err != nil {
		return fmt.Errorf("write sandbox configuration: %w", err)
	}
	if out.ExitCode != 0 {
		return fmt.Errorf("write sandbox configuration: %s", sandbox.FirstError(out.Stderr))
	}
	return nil
}

func recoverySettings(t source.RecoveryTarget) string {
	var b strings.Builder
	fmt.Fprintf(&b, "restore_command = 'cp %s/%%f \"%%p\"'\n", sandbox.WALDir)
	b.WriteString("recovery_target_timeline = 'latest'\nrecovery_target_action = 'promote'\n")
	switch {
	case !t.Time.IsZero():
		fmt.Fprintf(&b, "recovery_target_time = '%s'\n", t.Time.UTC().Format("2006-01-02 15:04:05.999999+00"))
	case t.LSN != "":
		fmt.Fprintf(&b, "recovery_target_lsn = '%s'\n", t.LSN)
	}
	return b.String()
}

var (
	verifyStatus = regexp.MustCompile(`(?m)^status:\s*(\S+)`)
	verifyBackup = regexp.MustCompile(`total files checked:\s*(\d+)`)
	verifyWAL    = regexp.MustCompile(`total WAL checked:\s*(\d+)`)
	verifyBad    = regexp.MustCompile(`(missing|checksum invalid|size invalid|other):\s*([1-9]\d*)`)
)

func parseVerify(text string) (ok bool, summary string) {
	m := verifyStatus.FindStringSubmatch(text)
	if m == nil {
		return false, "pgbackrest verify gave no status"
	}
	if m[1] == "ok" {
		files, wal := "0", "0"
		if f := verifyBackup.FindStringSubmatch(text); f != nil {
			files = f[1]
		}
		if w := verifyWAL.FindStringSubmatch(text); w != nil {
			wal = w[1]
		}
		return true, fmt.Sprintf("pgbackrest verify · %s files · %s WAL · 0 errors", files, wal)
	}
	var bad []string
	for _, b := range verifyBad.FindAllStringSubmatch(text, -1) {
		bad = append(bad, b[1]+": "+b[2])
	}
	if len(bad) == 0 {
		for line := range strings.SplitSeq(text, "\n") {
			t := strings.TrimSpace(line)
			if t != "" && !strings.HasPrefix(t, "stanza:") && !strings.HasPrefix(t, "status:") {
				bad = append(bad, t)
				break
			}
		}
	}
	return false, "pgbackrest verify · status " + m[1] + " · " + strings.Join(bad, ", ")
}

func (s *Source) Verify(ctx context.Context, ref source.BackupRef, _ sandbox.Instance) (source.VerifyResult, error) {
	res := source.VerifyResult{Tool: "pgbackrest verify"}
	err := s.withToolInstance(ctx, func(inst sandbox.Instance) error {
		out, err := inst.RunJob(ctx, s.job("pgbackrest", "verify", "--set="+ref.Label, "--output=text", "--verbose"))
		if err != nil {
			return fmt.Errorf("run pgbackrest verify: %w", err)
		}
		if out.ExitCode != 0 {
			res.Summary = fmt.Sprintf("pgbackrest verify exited %d: %s", out.ExitCode, toolError(out))
			return nil
		}
		res.OK, res.Summary = parseVerify(out.Stdout)
		return nil
	})
	return res, err
}

var minimumTool = map[int][2]int{14: {2, 34}, 15: {2, 39}, 16: {2, 46}, 17: {2, 52}, 18: {2, 55}}

func SupportsMajor(tool string, major int) (bool, string) {
	need, known := minimumTool[major]
	if !known {
		return false, "a supported PostgreSQL version"
	}
	want := fmt.Sprintf("%d.%d", need[0], need[1])
	parts := strings.Split(tool, ".")
	if len(parts) < 2 {
		return false, want
	}
	maj, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(leadingDigits.FindString(parts[1]))
	if err1 != nil || err2 != nil {
		return false, want
	}
	return maj > need[0] || (maj == need[0] && minor >= need[1]), want
}
