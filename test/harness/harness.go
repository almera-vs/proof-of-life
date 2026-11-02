//go:build integration

package harness

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/almera-vs/proof-of-life/internal/report"
)

const (
	s3Key    = "pol-test-access"
	s3Secret = "pol-test-secret-key"
	Cipher   = "pol-test-cipher-pass"
	Bucket   = "pol-test"
	Stanza   = "billing"
	PGPass   = "pol-test-only"
)

var (
	buildOnce sync.Once
	polPath   string
	buildErr  error
)

func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func Pol(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "pol-bin-")
		if err != nil {
			buildErr = err
			return
		}
		polPath = filepath.Join(dir, "pol")
		cmd := exec.Command("go", "build", "-o", polPath, "./cmd/pol")
		cmd.Dir = RepoRoot()
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		out, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("build pol: %v: %s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return polPath
}

func Major() int {
	if v, err := strconv.Atoi(os.Getenv("POL_TEST_PG_MAJOR")); err == nil {
		return v
	}
	return 17
}

type Workspace struct {
	Dir    string
	Config string
	Env    []string
	t      *testing.T
}

func NewWorkspace(t *testing.T) *Workspace {
	t.Helper()
	w := &Workspace{Dir: t.TempDir(), t: t}
	w.Config = filepath.Join(w.Dir, "drill.yaml")
	res := w.Pol("evidence", "keygen", "--out", w.KeyPath())
	if res.Exit != 0 {
		t.Fatalf("keygen: %s", res.Stderr)
	}
	return w
}

func (w *Workspace) KeyPath() string { return filepath.Join(w.Dir, "key") }

func (w *Workspace) PubPath() string { return w.KeyPath() + ".pub" }

func (w *Workspace) EvidencePath() string { return filepath.Join(w.Dir, "evidence.jsonl") }

func (w *Workspace) ReportDir() string { return filepath.Join(w.Dir, "reports") }

func (w *Workspace) CommonConfig() string {
	return fmt.Sprintf("evidence: { path: %s, sign_key: %s }\nreport: { dir: %s }\n", w.EvidencePath(), w.KeyPath(), w.ReportDir())
}

func (w *Workspace) WriteConfig(body string) {
	w.t.Helper()
	if err := os.WriteFile(w.Config, []byte(body+"\n"+w.CommonConfig()), 0o600); err != nil {
		w.t.Fatal(err)
	}
}

type Result struct {
	Exit   int
	Stdout string
	Stderr string
}

func (w *Workspace) Pol(args ...string) Result {
	w.t.Helper()
	cmd := exec.Command(Pol(w.t), args...)
	cmd.Env = append(os.Environ(), w.Env...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	exit := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			w.t.Fatalf("run pol: %v", err)
		}
		exit = ee.ExitCode()
	}
	return Result{Exit: exit, Stdout: so.String(), Stderr: se.String()}
}

func (w *Workspace) Start(args ...string) *exec.Cmd {
	w.t.Helper()
	cmd := exec.Command(Pol(w.t), args...)
	cmd.Env = append(os.Environ(), w.Env...)
	if err := cmd.Start(); err != nil {
		w.t.Fatal(err)
	}
	return cmd
}

var runIDPattern = regexp.MustCompile(`· run ([0-9a-f]+)`)

func (w *Workspace) Report(res Result) *report.Report {
	w.t.Helper()
	m := runIDPattern.FindStringSubmatch(res.Stdout)
	if m == nil {
		w.t.Fatalf("no run id in output:\n%s\n%s", res.Stdout, res.Stderr)
	}
	r, err := report.Load(w.ReportDir(), m[1])
	if err != nil {
		w.t.Fatalf("load report: %v\nstdout:\n%s\nstderr:\n%s", err, res.Stdout, res.Stderr)
	}
	return r
}

func Check(t *testing.T, r *report.Report, id string) report.Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("check %s is not in the report", id)
	return report.Check{}
}

func RequireNoCustomerData(t *testing.T, w *Workspace, res Result) {
	t.Helper()
	if strings.Contains(res.Stdout+res.Stderr, Sentinel) {
		t.Errorf("customer data in output: %s", Sentinel)
	}
	err := filepath.WalkDir(w.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), Sentinel) {
			t.Errorf("customer data in %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func RequireFail(t *testing.T, w *Workspace, res Result, id, text string) *report.Report {
	t.Helper()
	RequireNoCustomerData(t, w, res)
	if res.Exit != 1 {
		t.Fatalf("exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", res.Exit, res.Stdout, lastLines(res.Stderr, 15))
	}
	r := w.Report(res)
	if r.Status != "fail" {
		t.Fatalf("status = %s", r.Status)
	}
	c := Check(t, r, id)
	if c.Status != "fail" {
		t.Fatalf("%s = %s (%s)\nstdout:\n%s", id, c.Status, c.Reason, res.Stdout)
	}
	if !strings.Contains(c.Reason, text) {
		t.Fatalf("%s reason %q does not contain %q", id, c.Reason, text)
	}
	return r
}

func RequirePass(t *testing.T, w *Workspace, res Result) *report.Report {
	t.Helper()
	RequireNoCustomerData(t, w, res)
	if res.Exit != 0 {
		t.Fatalf("exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.Exit, res.Stdout, lastLines(res.Stderr, 15))
	}
	r := w.Report(res)
	if r.Status != "pass" {
		t.Fatalf("status = %s\n%s", r.Status, res.Stdout)
	}
	return r
}

func (w *Workspace) VerifyEvidence() {
	w.t.Helper()
	res := w.Pol("evidence", "verify", "--log", w.EvidencePath(), "--pub", w.PubPath())
	if res.Exit != 0 {
		w.t.Fatalf("evidence does not verify: %s %s", res.Stdout, res.Stderr)
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

type Stack struct {
	t       *testing.T
	Major   int
	Network string
	PG      testcontainers.Container
	MinIO   testcontainers.Container
	S3      *minio.Client
	DSN     string

	AdminDSN     string
	HeartbeatDSN string
	Workspace    *Workspace
}

type StackOptions struct {
	Encrypted bool

	NoChecksums bool

	PosixRepo string

	InitDBArgs string

	BootstrapUser string

	Env map[string]string
}

func tlsFiles(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "minio"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"minio", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func startMinIO(ctx context.Context, t *testing.T, net string) (testcontainers.Container, *minio.Client) {
	t.Helper()
	cert, key := tlsFiles(t)
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          "cgr.dev/chainguard/minio:latest",
			User:           "0",
			Env:            map[string]string{"MINIO_ROOT_USER": s3Key, "MINIO_ROOT_PASSWORD": s3Secret},
			Cmd:            []string{"server", "/data", "--certs-dir", "/certs"},
			ExposedPorts:   []string{"9000/tcp"},
			Networks:       []string{net},
			NetworkAliases: map[string][]string{net: {"minio"}},
			Files: []testcontainers.ContainerFile{
				{Reader: bytes.NewReader(cert), ContainerFilePath: "/certs/public.crt", FileMode: 0o644},
				{Reader: bytes.NewReader(key), ContainerFilePath: "/certs/private.key", FileMode: 0o644},
			},
			WaitingFor: wait.ForLog("API:").WithStartupTimeout(time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start minio: %v", err)
	}
	testcontainers.CleanupContainer(t, c)
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := c.MappedPort(ctx, "9000/tcp")
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client, err := minio.New(net2addr(host, port.Port()), &minio.Options{
		Creds: credentials.NewStaticV4(s3Key, s3Secret, ""), Secure: true, Region: "us-east-1",
		Transport: tr, BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		err = client.MakeBucket(ctx, Bucket, minio.MakeBucketOptions{Region: "us-east-1"})
		if err == nil {
			return c, client
		}
		if time.Now().After(deadline) {
			t.Fatalf("create bucket: %v", err)
		}
		time.Sleep(time.Second)
	}
}

func net2addr(host, port string) string { return net.JoinHostPort(host, port) }

func pgEnv(opts StackOptions) map[string]string {
	env := map[string]string{
		"POSTGRES_PASSWORD":                   PGPass,
		"POSTGRES_DB":                         "billing",
		"PGBACKREST_STANZA":                   Stanza,
		"PGBACKREST_REPO1_TYPE":               "s3",
		"PGBACKREST_REPO1_PATH":               "/pgbackrest",
		"PGBACKREST_REPO1_S3_BUCKET":          Bucket,
		"PGBACKREST_REPO1_S3_REGION":          "us-east-1",
		"PGBACKREST_REPO1_S3_ENDPOINT":        "minio",
		"PGBACKREST_REPO1_STORAGE_PORT":       "9000",
		"PGBACKREST_REPO1_S3_URI_STYLE":       "path",
		"PGBACKREST_REPO1_S3_KEY":             s3Key,
		"PGBACKREST_REPO1_S3_KEY_SECRET":      s3Secret,
		"PGBACKREST_REPO1_STORAGE_VERIFY_TLS": "n",
		"PGBACKREST_REPO1_RETENTION_FULL":     "9",
		"PGBACKREST_PG1_PATH":                 "/var/lib/postgresql/pgdata",
		"PGBACKREST_LOG_LEVEL_CONSOLE":        "warn",
		"PGDATA":                              "/var/lib/postgresql/pgdata",
	}
	if opts.PosixRepo != "" {
		env["PGBACKREST_REPO1_TYPE"] = "posix"
		env["PGBACKREST_REPO1_PATH"] = "/pol-repo"
	}
	if opts.Encrypted {
		env["PGBACKREST_REPO1_CIPHER_TYPE"] = "aes-256-cbc"
		env["PGBACKREST_REPO1_CIPHER_PASS"] = Cipher
	}
	if opts.NoChecksums && Major() >= 18 {
		env["POSTGRES_INITDB_ARGS"] = "--no-data-checksums"
	}
	if opts.InitDBArgs != "" {
		env["POSTGRES_INITDB_ARGS"] = strings.TrimSpace(env["POSTGRES_INITDB_ARGS"] + " " + opts.InitDBArgs)
	}
	if opts.BootstrapUser != "" {
		env["POSTGRES_USER"] = opts.BootstrapUser
		env["PGUSER"] = opts.BootstrapUser
		env["PGBACKREST_PG1_USER"] = opts.BootstrapUser
	}
	for k, v := range opts.Env {
		env[k] = v
	}
	return env
}

func NewStack(t *testing.T, opts StackOptions) *Stack {
	t.Helper()
	ctx := context.Background()
	nw, err := network.New(ctx)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	testcontainers.CleanupNetwork(t, nw)
	s := &Stack{t: t, Major: Major(), Network: nw.Name}
	s.MinIO, s.S3 = startMinIO(ctx, t, nw.Name)
	major := strconv.Itoa(s.Major)
	pg, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context: filepath.Join(RepoRoot(), "deploy", "demo"), Dockerfile: "postgres.Dockerfile",
				BuildArgs: map[string]*string{"PG_MAJOR": &major}, Repo: "pol-test-postgres", Tag: major, KeepImage: true,
			},
			Env:          pgEnv(opts),
			ExposedPorts: []string{"5432/tcp"},
			Networks:     []string{nw.Name},
			HostConfigModifier: func(hc *container.HostConfig) {
				if opts.PosixRepo != "" {
					hc.Binds = append(hc.Binds, opts.PosixRepo+":/pol-repo")
				}
			},
			Cmd: []string{
				"-c", "wal_level=replica", "-c", "archive_mode=on",
				"-c", "archive_command=pgbackrest archive-push %p", "-c", "archive_timeout=2",
				"-c", "max_wal_senders=2",
			},
			WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	testcontainers.CleanupContainer(t, pg)
	s.PG = pg
	host, err := pg.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := pg.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := "postgres"
	if opts.BootstrapUser != "" {
		bootstrap = opts.BootstrapUser
	}
	addr := net2addr(host, port.Port())
	s.AdminDSN = fmt.Sprintf("postgres://%s:%s@%s/billing?sslmode=disable", bootstrap, PGPass, addr)
	s.DSN = fmt.Sprintf("postgres://pol_fingerprint:change-me@%s/billing?sslmode=disable", addr)
	s.HeartbeatDSN = fmt.Sprintf("postgres://pol_heartbeat:change-me@%s/billing?sslmode=disable", addr)
	s.Shell("pgbackrest stanza-create")
	s.SQL(Seed)
	s.SQL(ShippedSQL(t, "roles.sql"))
	s.SQL(ShippedSQL(t, "heartbeat.sql"))
	w := NewWorkspace(t)
	w.Env = []string{"AWS_ACCESS_KEY_ID=" + s3Key, "AWS_SECRET_ACCESS_KEY=" + s3Secret, "POL_DSN=" + s.DSN, "POL_HB=" + s.HeartbeatDSN, "POL_CIPHER=" + Cipher}
	s.Workspace = w
	s.WriteDrill(DrillOptions{Encrypted: opts.Encrypted, PosixRepo: opts.PosixRepo})
	return s
}

func ShippedSQL(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(RepoRoot(), "deploy", "sql", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const Sentinel = "SENTINEL-CUSTOMER-VALUE-4111"

var Seed = `
CREATE EXTENSION pg_trgm;
CREATE TYPE invoice_state AS ENUM ('open', 'paid');
CREATE DOMAIN positive_amount AS numeric CHECK (VALUE > 0);
CREATE TYPE money_pair AS (low numeric, high numeric);
CREATE TYPE float_span AS RANGE (subtype = float8);
CREATE TABLE customers (id bigint PRIMARY KEY, name text NOT NULL);
CREATE INDEX customers_name_trgm ON customers USING gin (name gin_trgm_ops);
CREATE TABLE invoices (
  id bigserial PRIMARY KEY,
  customer_id bigint NOT NULL REFERENCES customers (id),
  amount positive_amount NOT NULL,
  state invoice_state NOT NULL DEFAULT 'open',
  note text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX invoices_created_at ON invoices (created_at);
CREATE INDEX invoices_open ON invoices (customer_id) WHERE state = 'open';
CREATE TABLE audit_log (id bigserial PRIMARY KEY, payload text);
CREATE TABLE accounts (
  id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email text COLLATE "C" UNIQUE,
  retired text,
  domain text GENERATED ALWAYS AS (split_part(email, '@', 2)) STORED,
  balance numeric CHECK (balance >= 0)
);
ALTER TABLE accounts DROP COLUMN retired;
ALTER TABLE accounts ADD COLUMN opened date DEFAULT '2020-01-01';
CREATE TABLE events (id bigint, at date NOT NULL, body text) PARTITION BY RANGE (at);
CREATE TABLE events_2025 PARTITION OF events FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
CREATE TABLE events_rest PARTITION OF events DEFAULT;
CREATE INDEX events_at ON events (at);
CREATE UNLOGGED TABLE scratch (id int);
INSERT INTO scratch SELECT generate_series(1, 5000);
CREATE VIEW open_invoices AS SELECT id, amount FROM invoices WHERE state = 'open';
CREATE FUNCTION invoice_count() RETURNS bigint LANGUAGE sql AS 'SELECT count(*) FROM invoices';
CREATE AGGREGATE sum_text(text) (SFUNC = textcat, STYPE = text);
CREATE PROCEDURE noop() LANGUAGE sql AS 'SELECT 1';
CREATE SEQUENCE report_numbers START 100 INCREMENT 5;
CREATE FUNCTION touch_note() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
CREATE TRIGGER invoices_touch BEFORE UPDATE ON invoices FOR EACH ROW EXECUTE FUNCTION touch_note();
INSERT INTO customers SELECT g, 'Customer ' || g FROM generate_series(1, 2000) g;
INSERT INTO invoices (customer_id, amount, note, created_at)
  SELECT (g % 2000) + 1, (g % 500) + 0.5, md5(g::text), now() - interval '1 day'
  FROM generate_series(1, 60000) g;
INSERT INTO accounts (email, balance) SELECT 'u' || g || '@example.com', g FROM generate_series(1, 300) g;
INSERT INTO events SELECT g, date '2025-01-01' + (g % 700), 'e' FROM generate_series(1, 3000) g;
INSERT INTO audit_log (payload) VALUES ('` + Sentinel + `');
CREATE MATERIALIZED VIEW invoice_totals AS SELECT customer_id, sum(amount) AS total FROM invoices GROUP BY customer_id;
ANALYZE;
`

type DrillOptions struct {
	Encrypted bool
	Cipher    string
	RTOTarget string
	MaxAge    string
	Heartbeat bool
	PosixRepo string
	ReadGID   int

	Assertions    string
	AmcheckBudget string
}

func (s *Stack) WriteDrill(o DrillOptions) {
	s.t.Helper()
	if o.RTOTarget == "" {
		o.RTOTarget = "30m"
	}
	if o.MaxAge == "" {
		o.MaxAge = "26h"
	}
	if o.AmcheckBudget == "" {
		o.AmcheckBudget = "5m"
	}
	cipher := ""
	if o.Encrypted {
		cipher = "  cipher_pass: { env: POL_CIPHER }\n"
	}
	repo := fmt.Sprintf(`    type: s3
    bucket: %s
    region: us-east-1
    path: /pgbackrest
    endpoint: minio
    port: 9000
    uri_style: path
    verify_tls: false
    credentials: { from_env: true }`, Bucket)
	if o.PosixRepo != "" {
		repo = "    type: posix\n    path: " + o.PosixRepo
		if o.ReadGID != 0 {
			repo += fmt.Sprintf("\n    read_gid: %d", o.ReadGID)
		}
	}
	body := fmt.Sprintf(`version: 1
drill: { name: billing, rto_target: %s, restore_timeout: 15m, max_age: %s }
source:
  type: pgbackrest
  stanza: %s
  repo:
%s
%srecovery: { target: latest }
fingerprint:
  dsn: { env: POL_DSN }
  exact_count_tables: [public.customers]
  row_count_tolerance: 0.5%%
  heartbeat: { enabled: %v, interval: 2s, dsn: { env: POL_HB } }
assertions:
  - name: invoices_before_backup
    sql: "SELECT count(*) FROM invoices WHERE created_at < :backup_stop_time"
    expect: { equals_fingerprint: true }
  - name: customer_rows
    sql: "SELECT count(*) FROM customers"
    expect: { equals: "2000" }
%ssandbox: { image: "postgres:{{major}}", cpus: 2, memory: 2GiB, restore_network: %s }
checks: { amcheck: { enabled: true, time_budget: %s } }
`, o.RTOTarget, o.MaxAge, Stanza, repo, cipher, o.Heartbeat, o.Assertions, s.Network, o.AmcheckBudget)
	s.Workspace.WriteConfig(body)
}

func (s *Stack) Shell(cmd string) string {
	s.t.Helper()
	out, code := s.ShellCode(cmd)
	if code != 0 {
		s.t.Fatalf("%s: exit %d: %s", cmd, code, out)
	}
	return out
}

func (s *Stack) ShellCode(cmd string) (string, int) {
	s.t.Helper()
	code, r, err := s.PG.Exec(context.Background(), []string{"su", "postgres", "-c", cmd}, tcMultiplexed())
	if err != nil {
		s.t.Fatalf("exec: %v", err)
	}
	var b bytes.Buffer
	if _, err := b.ReadFrom(r); err != nil {
		s.t.Fatal(err)
	}
	return b.String(), code
}

func (s *Stack) SQL(sql string) string {
	s.t.Helper()
	f := fmt.Sprintf("/tmp/s%d.sql", time.Now().UnixNano())
	if err := s.PG.CopyToContainer(context.Background(), []byte(sql), f, 0o644); err != nil {
		s.t.Fatal(err)
	}
	return strings.TrimSpace(s.Shell("psql -X -q -At -v ON_ERROR_STOP=1 -d billing -f " + f))
}

func (s *Stack) Backup(kind string) string {
	s.t.Helper()
	s.Shell("pgbackrest backup --start-fast --type=" + kind)
	return s.LatestLabel()
}

var labelPattern = regexp.MustCompile(`"label":"([^"]+)"`)

func (s *Stack) LatestLabel() string {
	s.t.Helper()
	m := labelPattern.FindAllStringSubmatch(s.Shell("pgbackrest info --output=json"), -1)
	if len(m) == 0 {
		s.t.Fatal("the repository holds no backups")
	}
	return m[len(m)-1][1]
}

func (s *Stack) SwitchWAL() {
	s.t.Helper()
	s.SQL("CREATE TEMP TABLE w AS SELECT 1; SELECT pg_switch_wal();")
	s.WaitArchived()
}

func (s *Stack) WaitArchived() {
	s.t.Helper()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		out := s.Shell(`psql -X -At -d billing -c "SELECT count(*) FROM pg_ls_archive_statusdir() WHERE name LIKE '%.ready'"`)
		if strings.TrimSpace(out) == "0" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	s.t.Fatal("the archiver did not catch up")
}

func (s *Stack) Capture() {
	s.t.Helper()
	res := s.Workspace.Pol("fingerprint", "capture", "-c", s.Workspace.Config)
	if res.Exit != 0 {
		s.t.Fatalf("fingerprint capture: %s\n%s", res.Stdout, res.Stderr)
	}
}

func (s *Stack) Objects(prefix string) []minio.ObjectInfo {
	s.t.Helper()
	var out []minio.ObjectInfo
	for o := range s.S3.ListObjects(context.Background(), Bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if o.Err != nil {
			s.t.Fatal(o.Err)
		}
		out = append(out, o)
	}
	return out
}

func (s *Stack) DamageObject(key string) {
	s.t.Helper()
	ctx := context.Background()
	obj, err := s.S3.GetObject(ctx, Bucket, key, minio.GetObjectOptions{})
	if err != nil {
		s.t.Fatal(err)
	}
	defer obj.Close()
	var b bytes.Buffer
	if _, err := b.ReadFrom(obj); err != nil {
		s.t.Fatal(err)
	}
	data := b.Bytes()
	for i := len(data) / 2; i < len(data)/2+16 && i < len(data); i++ {
		data[i] ^= 0xff
	}
	if _, err := s.S3.PutObject(ctx, Bucket, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{}); err != nil {
		s.t.Fatal(err)
	}
}

func (s *Stack) RemoveObject(key string) {
	s.t.Helper()
	if err := s.S3.RemoveObject(context.Background(), Bucket, key, minio.RemoveObjectOptions{}); err != nil {
		s.t.Fatal(err)
	}
}

func (s *Stack) S3Address(t *testing.T) (host, port string) {
	t.Helper()
	ctx := context.Background()
	host, err := s.MinIO.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.MinIO.MappedPort(ctx, "9000/tcp")
	if err != nil {
		t.Fatal(err)
	}
	return host, p.Port()
}
