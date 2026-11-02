//go:build integration

package fault

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/almera-vs/proof-of-life/internal/sandbox/docker"
	"github.com/almera-vs/proof-of-life/test/harness"
)

func TestTruncatedDump(t *testing.T) {
	s := harness.NewDumpStack(t, harness.Major())
	path := s.Dump("billing-1.dump", "c")
	s.Capture()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, info.Size()/2); err != nil {
		t.Fatal(err)
	}
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	harness.RequireFail(t, s.Workspace, res, "restore.completes", "pg_restore stopped")
	s.Workspace.VerifyEvidence()
}

func TestDumpTruncatedInsideHeader(t *testing.T) {
	s := harness.NewDumpStack(t, harness.Major())
	path := s.Dump("billing-1.dump", "c")
	s.Capture()
	if err := os.Truncate(path, 12); err != nil {
		t.Fatal(err)
	}
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	harness.RequireFail(t, s.Workspace, res, "backup.integrity", "not a readable pg_dump archive")
}

func TestCorruptedBackupFile(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	label := s.Backup("full")
	s.SwitchWAL()
	s.Capture()
	objects := s.Objects("pgbackrest/backup/" + harness.Stanza + "/" + label + "/pg_data/base/")
	if len(objects) == 0 {
		t.Fatal("no backup files found")
	}
	slices.SortFunc(objects, func(a, b minioObject) int { return int(b.Size - a.Size) })
	s.DamageObject(objects[0].Key)
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	r := harness.RequireFail(t, s.Workspace, res, "backup.integrity", "checksum invalid")
	if c := harness.Check(t, r, "restore.completes"); c.Status != "fail" {
		t.Errorf("restore.completes = %s (%s)", c.Status, c.Reason)
	}
	s.Workspace.VerifyEvidence()
}

func segments(s *harness.Stack) []string {
	var keys []string
	for _, o := range s.Objects("pgbackrest/archive/" + harness.Stanza + "/") {
		if segmentName.MatchString(o.Key) {
			keys = append(keys, o.Key)
		}
	}
	slices.Sort(keys)
	return keys
}

var segmentName = regexp.MustCompile(`/([0-9A-F]{24})-[0-9a-f]{40}`)

func TestMissingWALBeforePITRTarget(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.Backup("full")
	s.Capture()
	before := segments(s)
	s.SQL("INSERT INTO audit_log (payload) VALUES ('a')")
	s.SwitchWAL()
	s.SQL("INSERT INTO audit_log (payload) VALUES ('b')")
	s.SwitchWAL()
	target := time.Now().UTC().Add(time.Second).Format(time.RFC3339)
	time.Sleep(2 * time.Second)
	s.SQL("INSERT INTO audit_log (payload) VALUES ('c')")
	s.SwitchWAL()
	after := segments(s)
	missing := ""
	for _, k := range after {
		if !slices.Contains(before, k) {
			missing = k
			break
		}
	}
	if missing == "" {
		t.Fatal("no segment was archived after the backup")
	}
	s.RemoveObject(missing)
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config, "--target-time", target)
	name := segmentName.FindStringSubmatch(missing)[1]
	r := harness.RequireFail(t, s.Workspace, res, "recovery.wal_continuity", name)
	if c := harness.Check(t, r, "recovery.pitr_target"); c.Status != "fail" {
		t.Errorf("recovery.pitr_target = %s (%s)", c.Status, c.Reason)
	}
}

func TestMissingWALAtLatestIsNotASilentPass(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.Backup("full")
	s.Capture()
	before := segments(s)
	for _, v := range []string{"a", "b", "c"} {
		s.SQL("INSERT INTO audit_log (payload) VALUES ('" + v + "')")
		s.SwitchWAL()
	}
	after := segments(s)
	var fresh []string
	for _, k := range after {
		if !slices.Contains(before, k) {
			fresh = append(fresh, k)
		}
	}
	if len(fresh) < 3 {
		t.Fatalf("expected at least 3 new segments, got %d", len(fresh))
	}
	s.RemoveObject(fresh[1])
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	r := harness.RequireFail(t, s.Workspace, res, "recovery.wal_continuity", segmentName.FindStringSubmatch(fresh[1])[1])
	if c := harness.Check(t, r, "server.starts"); c.Status != "pass" {
		t.Logf("server.starts = %s; the hole is what this scenario proves either way", c.Status)
	}
}

func TestWrongPassphrase(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{Encrypted: true})
	s.Backup("full")
	s.Capture()
	s.Workspace.Env = append(s.Workspace.Env, "POL_CIPHER=not-the-right-passphrase")
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	r := harness.RequireFail(t, s.Workspace, res, "backup.integrity", "passphrase")
	if strings.ContainsRune(c(t, r), '�') {
		t.Error("the reason quotes undecrypted bytes")
	}
}

func TestOlderToolAgainstNewerServer(t *testing.T) {
	major := max(harness.Major(), 15)
	s := harness.NewDumpStack(t, major)
	s.Dump("billing-1.dump", "c")
	s.Capture()
	time.Sleep(1100 * time.Millisecond)
	stderr, exit := s.OlderToolDump(major-1, "billing-2.dump")
	if exit == 0 || !strings.Contains(stderr, "version mismatch") {
		t.Fatalf("expected the older pg_dump to refuse: exit %d: %s", exit, stderr)
	}
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	harness.RequireFail(t, s.Workspace, res, "tooling.version_drift", fmt.Sprintf("PostgreSQL %d", major))
	if !strings.Contains(res.Stdout, "billing-2.dump") {
		t.Fatalf("the drill should have picked the newest, empty archive:\n%s", res.Stdout)
	}
}

func TestTableDroppedAfterFingerprint(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.Backup("full")
	s.Capture()
	s.SQL("DROP TABLE audit_log")
	s.Backup("full")
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	r := harness.RequireFail(t, s.Workspace, res, "schema.fingerprint", "relation public.audit_log is in production but missing")
	if c := harness.Check(t, r, "restore.completes"); c.Status != "pass" {
		t.Errorf("the restore itself should work: %s", c.Status)
	}
}

func TestCorruptedHeapPage(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{NoChecksums: true})
	s.SQL("SELECT count(*) FROM invoices; CHECKPOINT;")
	path := s.SQL("SELECT current_setting('data_directory') || '/' || pg_relation_filepath('invoices')")
	corruptFirstTuple(t, s, path)
	s.Backup("full")
	s.Capture()
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	harness.RequireFail(t, s.Workspace, res, "integrity.amcheck", "invoices")
}

func TestCorruptedBtreeIndex(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{NoChecksums: true})
	s.SQL("SET enable_seqscan = off; SELECT count(*) FROM customers WHERE id > 0; CHECKPOINT;")
	path := s.SQL("SELECT current_setting('data_directory') || '/' || pg_relation_filepath('customers_pkey')")
	const page = 8192
	a, b := page+24+4*2, page+24+4*40
	first := s.Shell(fmt.Sprintf(`od -An -tx1 -j%d -N4 %s | tr -d ' \n'`, a, path))
	second := s.Shell(fmt.Sprintf(`od -An -tx1 -j%d -N4 %s | tr -d ' \n'`, b, path))
	if first == second {
		t.Fatal("expected two different line pointers")
	}
	writeHex(s, path, a, second)
	writeHex(s, path, b, first)
	s.Backup("full")
	s.Capture()
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	harness.RequireFail(t, s.Workspace, res, "integrity.amcheck", "customers_pkey")
}

func writeHex(s *harness.Stack, path string, offset int, hex string) {
	var octal strings.Builder
	for i := 0; i+1 < len(hex); i += 2 {
		v, err := strconv.ParseUint(hex[i:i+2], 16, 8)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(&octal, "\\%03o", v)
	}
	s.Shell(fmt.Sprintf(`printf '%s' | dd of=%s bs=1 seek=%d conv=notrunc 2>/dev/null`, octal.String(), path, offset))
}

func TestCopyErrorQuotingARowStaysOut(t *testing.T) {
	s := harness.NewDumpStack(t, harness.Major())
	s.SQLFile("billing", `
CREATE FUNCTION allowed(text) RETURNS boolean LANGUAGE sql IMMUTABLE
  AS $$ SELECT coalesce(current_setting('pol.allow', true) = 'on', false) $$;
CREATE TABLE guarded (payload text CHECK (allowed(payload)));
SET pol.allow = 'on';
INSERT INTO guarded VALUES ('`+harness.Sentinel+`');
`)
	s.Dump("billing-1.dump", "c")
	s.Capture()
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	r := harness.RequireFail(t, s.Workspace, res, "restore.completes", "guarded")
	if strings.Contains(harness.Check(t, r, "restore.completes").Reason, "Failing row") {
		t.Fatal("the reason quotes PostgreSQL's row detail")
	}
}

func corruptFirstTuple(t *testing.T, s *harness.Stack, path string) {
	t.Helper()
	hex := strings.TrimSpace(s.Shell(fmt.Sprintf(`od -An -tx1 -j24 -N4 %s | tr -d ' \n'`, path)))
	raw, err := strconv.ParseUint(hex, 16, 32)
	if err != nil || len(hex) != 8 {
		t.Fatalf("read line pointer %q: %v", hex, err)
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(raw))
	offset := binary.LittleEndian.Uint32(b[:]) & 0x7fff
	if offset == 0 {
		t.Fatal("the first line pointer is empty")
	}
	s.Shell(fmt.Sprintf(`printf '\377\377\377\177' | dd of=%s bs=1 seek=%d conv=notrunc 2>/dev/null`, path, offset))
}

func TestRestoreSlowerThanRTOTarget(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.Backup("full")
	s.Capture()
	s.WriteDrill(harness.DrillOptions{RTOTarget: "1s"})
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	r := harness.RequireFail(t, s.Workspace, res, "rto.within_target", "longer than the 1s target")
	for _, id := range []string{"restore.completes", "server.starts", "schema.fingerprint"} {
		if c := harness.Check(t, r, id); c.Status != "pass" {
			t.Errorf("%s = %s (%s); only the RTO should fail", id, c.Status, c.Reason)
		}
	}
}

func TestBackupOlderThanMaxAge(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.Backup("full")
	s.Capture()
	s.WriteDrill(harness.DrillOptions{MaxAge: "1s"})
	time.Sleep(2 * time.Second)
	res := s.Workspace.Pol("run", "-c", s.Workspace.Config)
	harness.RequireFail(t, s.Workspace, res, "backup.freshness", "older than max_age")
}

func TestKilledMidDrillLeavesNoOrphans(t *testing.T) {
	s := harness.NewStack(t, harness.StackOptions{})
	s.Backup("full")
	s.Capture()
	cmd := s.Workspace.Start("run", "-c", s.Workspace.Config)
	sb, err := docker.New("")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		res, err := sb.Collect(ctx, docker.GCOptions{DryRun: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Skipped) > 0 {

			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the drill never created a sandbox")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	before, err := sb.Collect(ctx, docker.GCOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if before.Containers+before.Volumes == 0 {
		t.Fatal("killing the drill should have left something for gc to find")
	}
	gc := s.Workspace.Pol("gc")
	if gc.Exit != 0 {
		t.Fatalf("gc: %s %s", gc.Stdout, gc.Stderr)
	}
	after, err := sb.Collect(ctx, docker.GCOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if after.Containers != 0 || after.Volumes != 0 || len(after.Runs) != 0 {
		t.Fatalf("orphans remain after gc: %+v", after)
	}

	harness.RequirePass(t, s.Workspace, s.Workspace.Pol("run", "-c", s.Workspace.Config))
}
