//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/almera-vs/proof-of-life/test/harness"
)

const tlAssertion = `  - name: row_on_new_timeline
    sql: "SELECT count(*) FROM audit_log WHERE payload = 'on timeline 2'"
    expect: { equals: "1" }
`

func TestShippedRolesAreConfined(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	ctx := context.Background()
	writes := []string{
		"INSERT INTO customers VALUES (999999, 'x')",
		"UPDATE customers SET name = 'x'",
		"DELETE FROM customers",
		"CREATE TABLE evil (id int)",
		"DROP TABLE customers",
		"TRUNCATE invoices",
		"SELECT payload FROM audit_log",
	}
	ro, err := pgx.Connect(ctx, s.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close(ctx)

	if _, err := ro.Exec(ctx, "CREATE TABLE evil_default (id int)"); err == nil {
		t.Error("a default pol_fingerprint session could create a table")
	}

	if s.Major < 15 {
		writes = slices.DeleteFunc(writes, func(sql string) bool { return strings.HasPrefix(sql, "CREATE TABLE") })
	}
	if _, err := ro.Exec(ctx, "SET default_transaction_read_only = off"); err != nil {
		t.Fatal(err)
	}
	for _, sql := range writes {
		if _, err := ro.Exec(ctx, sql); err == nil {
			t.Errorf("pol_fingerprint could run: %s", sql)
		}
	}
	var n int
	if err := ro.QueryRow(ctx, "SELECT count(*) FROM customers").Scan(&n); err != nil || n != 2000 {
		t.Errorf("pol_fingerprint should read listed tables: %d %v", n, err)
	}

	hb, err := pgx.Connect(ctx, s.HeartbeatDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer hb.Close(ctx)
	for _, sql := range append(writes, "SELECT count(*) FROM customers") {
		if _, err := hb.Exec(ctx, sql); err == nil {
			t.Errorf("pol_heartbeat could run: %s", sql)
		}
	}
	if _, err := hb.Exec(ctx, "INSERT INTO pol_heartbeat VALUES (now())"); err != nil {
		t.Errorf("pol_heartbeat should write its own table: %v", err)
	}

	s.Backup("full")
	res := s.Workspace.Pol("validate", "-c", s.Workspace.Config)
	if res.Exit != 0 || strings.Contains(res.Stdout, "should be read-only") {
		t.Errorf("validate on the shipped role: exit %d\n%s", res.Exit, res.Stdout)
	}
	s.Workspace.Env = append(s.Workspace.Env, "POL_DSN="+s.AdminDSN)
	res = s.Workspace.Pol("validate", "-c", s.Workspace.Config)
	if !strings.Contains(res.Stdout, "the fingerprint role has superuser") {
		t.Errorf("validate should flag a superuser:\n%s", res.Stdout)
	}
}

func TestSandboxConfinement(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.Backup("full")
	s.Capture()
	s.SwitchWAL()
	stop := harness.WatchSandboxes(t)
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	seen := stop()
	harness.RequirePass(t, s.Workspace, res)
	servers, jobs := 0, 0
	for _, c := range seen {
		harness.RequireConfined(t, c)
		switch {
		case c.IsServer():
			servers++
			if c.HostConfig.NetworkMode != "none" {
				t.Errorf("the server has a network: %s", c.HostConfig.NetworkMode)
			}
		case c.HostConfig.NetworkMode != "none":
			jobs++
			if c.HostConfig.NetworkMode != s.Network {
				t.Errorf("a job is on %s, not the restore network", c.HostConfig.NetworkMode)
			}
			if !strings.HasPrefix(imageName(c), "sha256:") && !strings.Contains(imageName(c), "pgbackrest") {
				t.Errorf("only the tool image should have a network: %s", imageName(c))
			}
		}
	}
	if servers != 1 || jobs == 0 {
		t.Fatalf("watched %d containers: %d servers, %d networked jobs", len(seen), servers, jobs)
	}
}

func imageName(c harness.SandboxContainer) string { return c.Image }

func TestPosixRepositoryReadThroughItsGroup(t *testing.T) {
	repo, err := os.MkdirTemp("", "pol-posix-owned-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(repo) })
	if err := os.Chmod(repo, 0o777); err != nil {
		t.Fatal(err)
	}
	s := harness.NewStack(t, harness.StackOptions{PosixRepo: repo})
	s.Backup("full")
	s.Capture()
	s.SwitchWAL()
	const uid, gid = 12345, 12346
	if code, _, err := s.PG.Exec(context.Background(), []string{"sh", "-c", fmt.Sprintf("chown -R %d:%d /pol-repo && chmod -R u=rwX,g=rX,o= /pol-repo", uid, gid)}); err != nil || code != 0 {
		t.Fatalf("chown: %d %v", code, err)
	}
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	if res.Exit != 4 || !strings.Contains(res.Stdout, "read_gid") {
		t.Fatalf("expected an infrastructure error naming read_gid, got exit %d:\n%s", res.Exit, res.Stdout)
	}
	s.WriteDrill(harness.DrillOptions{PosixRepo: repo, ReadGID: gid})
	harness.RequirePass(t, s.Workspace, s.Workspace.Pol("run", "-c", s.Workspace.Config))
}

func TestPgDumpOfThePostgresDatabase(t *testing.T) {
	s := harness.NewDumpStack(t, harness.Major())
	s.SQLFile("postgres", "CREATE TABLE kept (id int); INSERT INTO kept VALUES (1), (2), (3);")
	s.DumpDB = "postgres"
	s.Dump("billing-1.dump", "c")
	w := s.Workspace
	w.WriteConfig(fmt.Sprintf(`version: 1
drill: { name: pg, rto_target: 30m, restore_timeout: 15m }
source:
  type: pgdump
  pattern: "billing-*"
  repo: { type: posix, path: %s }
assertions:
  - name: rows
    sql: "SELECT count(*) FROM kept"
    expect: { equals: "3" }
sandbox: { image: "postgres:{{major}}", cpus: 2, memory: 2GiB }
checks: { amcheck: { enabled: true, time_budget: 5m } }
`, s.Dumps))
	r := harness.RequirePass(t, w, w.Pol("run", "-c", w.Config))
	if c := harness.Check(t, r, "data.assertions"); c.Status != "pass" {
		t.Fatalf("%+v", c)
	}
}

func TestClusterWithoutThePostgresDatabase(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{Env: map[string]string{"PGBACKREST_PG1_DATABASE": "billing"}})
	s.SQL("DROP DATABASE postgres")
	s.Backup("full")
	s.Capture()
	s.SwitchWAL()
	harness.RequirePass(t, s.Workspace, s.Workspace.Pol("run", "-c", s.Workspace.Config))
}

func TestDifferentialAndIncrementalBackups(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.Backup("full")
	s.SQL("INSERT INTO customers SELECT g, 'd' FROM generate_series(2001, 2100) g")
	diff := s.Backup("diff")
	if !strings.HasSuffix(diff, "D") {
		t.Fatalf("label %s", diff)
	}
	s.WriteDrill(harness.DrillOptions{Assertions: `  - name: rows_through_diff
    sql: "SELECT count(*) FROM customers WHERE id BETWEEN 2001 AND 2100"
    expect: { equals: "100" }
`})
	s.Capture()
	s.SwitchWAL()

	r := runExpectingOnly(t, s, "data.assertions")
	if r != diff {
		t.Fatalf("drilled %s, want %s", r, diff)
	}

	s.SQL("INSERT INTO customers SELECT g, 'i' FROM generate_series(2101, 2200) g")
	incr := s.Backup("incr")
	if !strings.HasSuffix(incr, "I") {
		t.Fatalf("label %s", incr)
	}
	s.Capture()
	s.SwitchWAL()
	if r := runExpectingOnly(t, s, "data.assertions"); r != incr {
		t.Fatalf("drilled %s, want %s", r, incr)
	}

	label := s.Objects("pgbackrest/backup/" + harness.Stanza + "/")
	var fullFile string
	for _, o := range label {
		if strings.Contains(o.Key, "F/pg_data/base/") && strings.HasSuffix(o.Key, ".gz") && o.Size > 4096 {
			fullFile = o.Key
			break
		}
	}
	if fullFile == "" {
		t.Fatal("no file found in the full backup")
	}
	s.DamageObject(fullFile)
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	if res.Exit != 1 {
		t.Fatalf("a damaged base must fail the drill: exit %d\n%s", res.Exit, res.Stdout)
	}
	report := s.Workspace.Report(res)
	if c := harness.Check(t, report, "restore.completes"); c.Status != "fail" {
		t.Fatalf("restore.completes = %s: %s\n%s", c.Status, c.Reason, res.Stdout)
	}
}

func runExpectingOnly(t *testing.T, s *harness.Stack, allowed string) string {
	t.Helper()
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	r := s.Workspace.Report(res)
	for _, c := range r.Checks {
		if c.ID == allowed {
			if !strings.Contains(c.Reason, "customer_rows") || strings.Contains(c.Reason, "rows_through_diff") {
				t.Fatalf("%s: %s", c.ID, c.Reason)
			}
			continue
		}
		if c.Status != "pass" {
			t.Fatalf("%s = %s: %s\n%s", c.ID, c.Status, c.Reason, res.Stdout)
		}
	}
	return r.Backup.Label
}

var tl2Segment = regexp.MustCompile(`/(00000002[0-9A-F]{16})-[0-9a-f]{40}`)

func TestTimelineSwitch(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.Backup("full")
	s.WriteDrill(harness.DrillOptions{Assertions: tlAssertion})
	s.Capture()
	time.Sleep(1100 * time.Millisecond)
	target := time.Now().UTC()
	time.Sleep(1100 * time.Millisecond)
	s.SQL("INSERT INTO audit_log (payload) VALUES ('stops recovery')")
	s.SwitchWAL()
	s.ForkTimeline(target)
	s.SQLOnFork("INSERT INTO audit_log (payload) VALUES ('on timeline 2')")
	s.SQLOnFork("INSERT INTO audit_log (payload) VALUES ('more')")
	s.SQLOnFork("INSERT INTO audit_log (payload) VALUES ('still more')")

	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	r := harness.RequirePass(t, s.Workspace, res)
	if c := harness.Check(t, r, "data.assertions"); c.Status != "pass" {
		t.Fatalf("the row written on timeline 2 was not recovered: %+v", c)
	}

	var fresh []string
	for _, o := range s.Objects("pgbackrest/archive/" + harness.Stanza + "/") {
		if tl2Segment.MatchString(o.Key) {
			fresh = append(fresh, o.Key)
		}
	}
	slices.Sort(fresh)
	if len(fresh) < 3 {
		t.Fatalf("expected at least 3 segments on timeline 2: %v", fresh)
	}
	s.RemoveObject(fresh[1])
	res = s.Workspace.Pol("run", "-c", s.Workspace.Config)
	harness.RequireFail(t, s.Workspace, res, "recovery.wal_continuity", tl2Segment.FindStringSubmatch(fresh[1])[1])
}

func TestNonDefaultWALSegmentSize(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{InitDBArgs: "--wal-segsize=32"})
	s.Backup("full")
	s.Capture()
	s.SwitchWAL()
	s.SQL("INSERT INTO audit_log (payload) VALUES ('x')")
	s.SwitchWAL()
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	r := harness.RequirePass(t, s.Workspace, res)
	if c := harness.Check(t, r, "recovery.wal_continuity"); c.Status != "pass" {
		t.Fatalf("%+v", c)
	}
}

func TestTablespacesPhysical(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.Shell("mkdir -p /tmp/ts1")
	s.SQL("CREATE TABLESPACE ts1 LOCATION '/tmp/ts1'")
	s.SQL(`CREATE TABLE placed (id int PRIMARY KEY USING INDEX TABLESPACE ts1, v text) TABLESPACE ts1;
CREATE INDEX placed_v ON placed (v) TABLESPACE ts1;
INSERT INTO placed SELECT g, 'v' FROM generate_series(1, 5000) g;
ANALYZE placed;`)
	s.Backup("full")
	s.Capture()
	s.SwitchWAL()
	r := harness.RequirePass(t, s.Workspace, s.Workspace.Pol("run", "-c", s.Workspace.Config))
	if r.Counts.Passed != 12 {
		t.Fatalf("%+v", r.Counts)
	}
}

func TestTablespacesLogical(t *testing.T) {
	s := harness.NewDumpStack(t, harness.Major())
	s.Exec("sh", "-c", "mkdir -p /tmp/ts1 && chown postgres /tmp/ts1")
	s.SQL("CREATE TABLESPACE ts1 LOCATION '/tmp/ts1'")
	s.SQLFile("billing", `CREATE TABLE placed (id int PRIMARY KEY USING INDEX TABLESPACE ts1, v text) TABLESPACE ts1;
CREATE INDEX placed_v ON placed (v) TABLESPACE ts1;
INSERT INTO placed SELECT g, 'v' FROM generate_series(1, 5000) g;
ANALYZE placed;`)
	s.Dump("billing-1.dump", "c")
	s.Capture()
	r := harness.RequirePass(t, s.Workspace, s.Workspace.Pol("run", "-c", s.Workspace.Config))
	if c := harness.Check(t, r, "schema.fingerprint"); c.Status != "pass" {
		t.Fatalf("%+v", c)
	}
}

func TestBootstrapRoleNotNamedPostgres(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{BootstrapUser: "acme_admin"})
	s.Backup("full")
	s.SwitchWAL()

	noRef := s.Workspace
	res := noRef.Pol("run", "-c", noRef.Config)
	if res.Exit == 0 || !strings.Contains(res.Stdout, "sandbox.superuser") {
		t.Fatalf("exit %d, no mention of sandbox.superuser:\n%s", res.Exit, res.Stdout)
	}
	s.Capture()
	harness.RequirePass(t, noRef, noRef.Pol("run", "-c", noRef.Config))
}

func TestMissingLocaleInALogicalRestore(t *testing.T) {
	s := harness.NewDumpStack(t, harness.Major())
	s.Exec("localedef", "--no-archive", "-i", "de_DE", "-f", "UTF-8", "de_DE.UTF-8")
	s.SQL("CREATE DATABASE german TEMPLATE template0 LOCALE 'de_DE.UTF-8'")
	s.SQLFile("german", "CREATE TABLE customers (id int);")
	s.DumpDB = "german"
	s.Dump("billing-1.dump", "c")
	w := s.Workspace
	w.WriteConfig(fmt.Sprintf(`version: 1
drill: { name: de, rto_target: 30m, restore_timeout: 15m }
source:
  type: pgdump
  pattern: "billing-*"
  repo: { type: posix, path: %s }
sandbox: { image: "postgres:{{major}}", cpus: 2, memory: 2GiB }
`, s.Dumps))
	res := w.Pol("run", "-c", w.Config)
	harness.RequireFail(t, w, res, "restore.completes", "does not have this locale")
}

func TestMissingLocaleInAPhysicalRestore(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	code, _, err := s.PG.Exec(context.Background(), []string{"localedef", "--no-archive", "-i", "de_DE", "-f", "UTF-8", "de_DE.UTF-8"})
	if err != nil || code != 0 {
		t.Fatalf("localedef: %d %v", code, err)
	}
	s.SQL("CREATE DATABASE german TEMPLATE template0 LOCALE 'de_DE.UTF-8'")
	s.Shell(`psql -X -q -d german -c "CREATE TABLE customers (id int); INSERT INTO customers SELECT generate_series(1, 2000); CREATE TABLE invoices (created_at timestamptz);"`)
	s.Workspace.Env = append(s.Workspace.Env, "POL_DSN="+strings.Replace(s.AdminDSN, "/billing?", "/german?", 1))
	s.Backup("full")
	s.Capture()
	s.SwitchWAL()
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	r := harness.RequireFail(t, s.Workspace, res, "schema.fingerprint", "locale")
	if c := harness.Check(t, r, "server.starts"); c.Status != "pass" {
		t.Errorf("the server itself starts: %+v", c)
	}
}

func TestMissingExtensionInALogicalRestore(t *testing.T) {
	s := harness.NewDumpStack(t, harness.Major())
	share := strings.TrimSpace(s.Exec("pg_config", "--sharedir"))
	s.Exec("sh", "-c", fmt.Sprintf(`cd %s/extension && printf "default_version = '1.0'\nrelocatable = true\n" > polx.control && echo "CREATE FUNCTION polx_one() RETURNS int LANGUAGE sql AS 'SELECT 1';" > polx--1.0.sql`, share))
	s.SQL("CREATE EXTENSION polx")
	s.Dump("billing-1.dump", "c")
	s.Capture()
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	harness.RequireFail(t, s.Workspace, res, "restore.completes", "polx")
}

func TestAmcheckBudgetWarns(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.Backup("full")
	s.WriteDrill(harness.DrillOptions{AmcheckBudget: "1ms"})
	s.Capture()
	s.SwitchWAL()
	w := s.Workspace
	res := w.Pol("run", "-c", w.Config)
	if res.Exit != 0 {
		t.Fatalf("exit %d\n%s", res.Exit, res.Stdout)
	}
	r := w.Report(res)
	c := harness.Check(t, r, "integrity.amcheck")
	if r.Status != "warn" || c.Status != "warn" || !strings.Contains(c.Reason, "was not checked") {
		t.Fatalf("%s %+v", r.Status, c)
	}
	if r.Title != "Restorable, with warnings." {
		t.Errorf("%s", r.Title)
	}
	for _, ctl := range r.Controls {
		if ctl.Name == "NIS2 Art. 21(2)(c)" && ctl.Status != "Partly evidenced" {
			t.Errorf("%+v", ctl)
		}
	}
	if strict := w.Pol("run", "-c", w.Config, "--strict"); strict.Exit != 2 {
		t.Fatalf("--strict exit %d\n%s", strict.Exit, strict.Stdout)
	}
}

func TestWALGapPastAReachedTargetWarns(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.Backup("full")
	s.Capture()
	time.Sleep(1100 * time.Millisecond)
	target := time.Now().UTC().Format(time.RFC3339)
	time.Sleep(1100 * time.Millisecond)
	s.SQL("INSERT INTO audit_log (payload) VALUES ('stops recovery here')")
	s.SwitchWAL()
	before := s.Objects("pgbackrest/archive/" + harness.Stanza + "/")
	for _, v := range []string{"a", "b", "c"} {
		s.SQL("INSERT INTO audit_log (payload) VALUES ('" + v + "')")
		s.SwitchWAL()
	}
	var fresh []string
	for _, o := range s.Objects("pgbackrest/archive/" + harness.Stanza + "/") {
		known := slices.ContainsFunc(before, func(b minioInfo) bool { return b.Key == o.Key })
		if !known && strings.HasSuffix(o.Key, ".gz") {
			fresh = append(fresh, o.Key)
		}
	}
	slices.Sort(fresh)
	if len(fresh) < 3 {
		t.Fatalf("expected at least 3 later segments: %v", fresh)
	}
	s.RemoveObject(fresh[1])
	w := s.Workspace
	res := w.Pol("run", "-c", w.Config, "--target-time", target)
	if res.Exit != 0 {
		t.Fatalf("the target was reachable: exit %d\n%s", res.Exit, res.Stdout)
	}
	r := w.Report(res)
	if c := harness.Check(t, r, "recovery.wal_continuity"); c.Status != "warn" || !strings.Contains(c.Reason, "would stop at the gap") {
		t.Fatalf("%+v", c)
	}
	if c := harness.Check(t, r, "recovery.pitr_target"); c.Status != "pass" {
		t.Fatalf("%+v", c)
	}
}
