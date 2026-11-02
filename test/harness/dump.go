//go:build integration

package harness

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

func tcMultiplexed() tcexec.ProcessOption { return tcexec.Multiplexed() }

type DumpStack struct {
	t         *testing.T
	Major     int
	Network   string
	PG        testcontainers.Container
	DSN       string
	AdminDSN  string
	Dumps     string
	Workspace *Workspace

	DumpDB string
}

func (s *DumpStack) dumpDB() string {
	if s.DumpDB != "" {
		return s.DumpDB
	}
	return "billing"
}

func NewDumpStack(t *testing.T, major int) *DumpStack {
	t.Helper()
	ctx := context.Background()
	nw, err := network.New(ctx)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	testcontainers.CleanupNetwork(t, nw)
	pg, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          "postgres:" + strconv.Itoa(major),
			Env:            map[string]string{"POSTGRES_PASSWORD": PGPass, "POSTGRES_DB": "billing"},
			ExposedPorts:   []string{"5432/tcp"},
			Networks:       []string{nw.Name},
			NetworkAliases: map[string][]string{nw.Name: {"pgsource"}},
			WaitingFor:     wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	testcontainers.CleanupContainer(t, pg)
	host, err := pg.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := pg.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatal(err)
	}
	addr := net2addr(host, port.Port())
	s := &DumpStack{
		t: t, Major: major, Network: nw.Name, PG: pg,
		DSN:      fmt.Sprintf("postgres://pol_fingerprint:change-me@%s/billing?sslmode=disable", addr),
		AdminDSN: fmt.Sprintf("postgres://postgres:%s@%s/billing?sslmode=disable", PGPass, addr),
	}
	s.Dumps = t.TempDir()
	s.SQLFile("billing", Seed)
	s.SQLFile("billing", ShippedSQL(t, "roles.sql"))
	s.Workspace = NewWorkspace(t)
	s.Workspace.Env = []string{"POL_DSN=" + s.DSN}
	s.WriteDrill()
	return s
}

func (s *DumpStack) exec(argv ...string) string {
	s.t.Helper()
	code, r, err := s.PG.Exec(context.Background(), argv, tcMultiplexed())
	if err != nil {
		s.t.Fatalf("exec: %v", err)
	}
	var b bytes.Buffer
	if _, err := b.ReadFrom(r); err != nil {
		s.t.Fatal(err)
	}
	if code != 0 {
		s.t.Fatalf("%v: exit %d: %s", argv, code, b.String())
	}
	return b.String()
}

func (s *DumpStack) SQLFile(db, sql string) string {
	s.t.Helper()
	f := fmt.Sprintf("/tmp/s%d.sql", time.Now().UnixNano())
	if err := s.PG.CopyToContainer(context.Background(), []byte(sql), f, 0o644); err != nil {
		s.t.Fatal(err)
	}
	return s.exec("psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", db, "-f", f)
}

func (s *DumpStack) Exec(argv ...string) string {
	s.t.Helper()
	return s.exec(argv...)
}

func (s *DumpStack) SQL(sql string) string {
	s.t.Helper()
	return s.exec("psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "billing", "-c", sql)
}

func (s *DumpStack) WriteDrill() {
	s.t.Helper()
	s.Workspace.WriteConfig(fmt.Sprintf(`version: 1
drill: { name: billing, rto_target: 30m, restore_timeout: 15m }
source:
  type: pgdump
  pattern: "billing-*"
  repo: { type: posix, path: %s }
fingerprint:
  dsn: { env: POL_DSN }
  exact_count_tables: [public.customers]
  row_count_tolerance: 0.5%%
assertions:
  - name: customer_rows
    sql: "SELECT count(*) FROM customers"
    expect: { equals_fingerprint: true }
sandbox: { image: "postgres:{{major}}", cpus: 2, memory: 2GiB }
checks: { amcheck: { enabled: true, time_budget: 5m } }
`, s.Dumps))
}

func (s *DumpStack) Dump(name, format string) string {
	s.t.Helper()
	inside := "/tmp/" + name
	s.exec("pg_dump", "-U", "postgres", "-d", s.dumpDB(), "-F"+format, "-f", inside)
	return s.copyOut(name, inside, format == "d")
}

func (s *DumpStack) copyOut(name, inside string, dir bool) string {
	s.t.Helper()
	ctx := context.Background()
	local := filepath.Join(s.Dumps, name)
	if !dir {
		s.copyFile(ctx, inside, local)
		return local
	}
	if err := os.MkdirAll(local, 0o755); err != nil {
		s.t.Fatal(err)
	}
	for _, f := range bytes.Fields([]byte(s.exec("ls", inside))) {
		s.copyFile(ctx, inside+"/"+string(f), filepath.Join(local, string(f)))
	}
	return local
}

func (s *DumpStack) copyFile(ctx context.Context, from, to string) {
	s.t.Helper()
	r, err := s.PG.CopyFileFromContainer(ctx, from)
	if err != nil {
		s.t.Fatalf("copy %s: %v", from, err)
	}
	defer r.Close()
	f, err := os.Create(to)
	if err != nil {
		s.t.Fatal(err)
	}
	defer f.Close()
	if _, err := io.Copy(f, r); err != nil {
		s.t.Fatal(err)
	}
}

func (s *DumpStack) Capture() {
	s.t.Helper()
	res := s.Workspace.Pol("fingerprint", "capture", "-c", s.Workspace.Config)
	if res.Exit != 0 {
		s.t.Fatalf("fingerprint capture: %s\n%s", res.Stdout, res.Stderr)
	}
}

func (s *DumpStack) OlderToolDump(olderMajor int, name string) (stderr string, exit int) {
	s.t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:      "postgres:" + strconv.Itoa(olderMajor),
			Entrypoint: []string{"sleep", "600"},
			Networks:   []string{s.Network},
			WaitingFor: wait.ForExec([]string{"true"}),
		},
		Started: true,
	})
	if err != nil {
		s.t.Fatalf("start pg_dump %d: %v", olderMajor, err)
	}
	testcontainers.CleanupContainer(s.t, c)
	script := fmt.Sprintf(`PGPASSWORD=%s pg_dump -Fc -h pgsource -U postgres -d billing > /tmp/out.dump 2>/tmp/err; code=$?; cat /tmp/err; exit $code`, PGPass)
	code, r, err := c.Exec(ctx, []string{"sh", "-c", script}, tcMultiplexed())
	if err != nil {
		s.t.Fatal(err)
	}
	var b bytes.Buffer
	if _, err := b.ReadFrom(r); err != nil {
		s.t.Fatal(err)
	}
	reader, err := c.CopyFileFromContainer(ctx, "/tmp/out.dump")
	if err != nil {
		s.t.Fatal(err)
	}
	defer reader.Close()
	f, err := os.Create(filepath.Join(s.Dumps, name))
	if err != nil {
		s.t.Fatal(err)
	}
	defer f.Close()
	if _, err := io.Copy(f, reader); err != nil {
		s.t.Fatal(err)
	}
	return b.String(), code
}
