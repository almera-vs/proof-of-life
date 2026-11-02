package fingerprint

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHashIgnoresOrderAndWhitespace(t *testing.T) {
	a := []Object{
		{Kind: "relation", Identity: "public.a", Definition: "kind=r"},
		{Kind: "column", Identity: "public.a.id", Definition: "type=int  \r\nnext"},
	}
	b := []Object{
		{Kind: "column", Identity: "public.a.id", Definition: "type=int\nnext\n"},
		{Kind: "relation", Identity: "public.a", Definition: "kind=r"},
	}
	if Hash(a) != Hash(b) {
		t.Fatal("hash should not depend on order or trailing whitespace")
	}
	b[0].Definition = "type=bigint\nnext"
	if Hash(a) == Hash(b) {
		t.Fatal("hash should change with a definition")
	}
}

func TestCompareSchemaExplainsDifferences(t *testing.T) {
	expected := []Object{
		{Kind: "relation", Identity: "public.gone", Definition: "kind=r"},
		{Kind: "column", Identity: "public.t.a", Definition: "type=integer"},
		{Kind: "function", Identity: "public.f()", Definition: "secret literal 4111"},
	}
	found := []Object{
		{Kind: "column", Identity: "public.t.a", Definition: "type=text"},
		{Kind: "relation", Identity: "public.new", Definition: "kind=r"},
		{Kind: "function", Identity: "public.f()", Definition: "other literal 4222"},
	}
	diffs := CompareSchema(expected, found)
	var text []string
	for _, d := range diffs {
		text = append(text, d.String())
	}
	joined := strings.Join(text, "\n")
	for _, want := range []string{
		"relation public.gone is in production but missing",
		`column public.t.a differs: expected "type=integer", found "type=text"`,
		"relation public.new is in the restored database but not in production",
		"function public.f() has a different definition",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "4111") {
		t.Error("function text leaked into the diff")
	}
	if CompareSchema(expected, expected) != nil {
		t.Error("identical lists should have no differences")
	}
}

func TestCompareCounts(t *testing.T) {
	snap := &Snapshot{
		ExactCounts: map[string]int64{"public.invoices": 100},
		Tables: []TableCount{
			{Table: "public.invoices", Estimate: 100},
			{Table: "public.big", Estimate: 1_000_000},
			{Table: "public.hot", Estimate: 1_000_000, Modified: 50_000},
			{Table: "public.fresh", Estimate: -1},
			{Table: "public.dropped", Estimate: 5000},
		},
	}
	res := CompareCounts(snap, map[string]int64{"public.invoices": 99},
		[]TableCount{
			{Table: "public.big", Estimate: 1_004_000},
			{Table: "public.hot", Estimate: 1_040_000},
			{Table: "public.fresh", Estimate: 3},
		}, 0.005)
	if res.Exact != 1 || res.Estimated != 3 || res.Unknown != 1 {
		t.Fatalf("%+v", res)
	}
	if len(res.Mismatches) != 2 {
		t.Fatalf("mismatches = %+v", res.Mismatches)
	}
	if got := res.Mismatches[0].String(); got != "public.invoices: expected exactly 100 rows, found 99" {
		t.Errorf("got %q", got)
	}
	if got := res.Mismatches[1].String(); got != "public.dropped: expected about 5000 rows, found 0, tolerance ±35" {
		t.Errorf("got %q", got)
	}
}

func TestCompareSettings(t *testing.T) {
	snap := &Snapshot{Encoding: "UTF8", Collate: "en_US.utf8", Ctype: "en_US.utf8", Extensions: map[string]string{"plpgsql": "1.0", "pg_trgm": "1.6"}}
	fails, warns := CompareSettings(snap, "UTF8", "en_US.utf8", "en_US.utf8", map[string]string{"plpgsql": "1.0", "pg_trgm": "1.6", "extra": "1"})
	if len(fails) != 0 || len(warns) != 0 {
		t.Fatalf("%v %v", fails, warns)
	}
	fails, warns = CompareSettings(snap, "LATIN1", "C", "en_US.utf8", map[string]string{"plpgsql": "1.0"})
	if len(fails) != 3 || len(warns) != 0 {
		t.Fatalf("%v %v", fails, warns)
	}
	_, warns = CompareSettings(snap, "UTF8", "en_US.utf8", "en_US.utf8", map[string]string{"plpgsql": "1.0", "pg_trgm": "1.5"})
	if len(warns) != 1 {
		t.Fatalf("%v", warns)
	}
}

func TestEstimateOutsideToleranceFails(t *testing.T) {
	snap := &Snapshot{Tables: []TableCount{{Table: "public.t", Estimate: 1_000_000}}}
	res := CompareCounts(snap, nil, []TableCount{{Table: "public.t", Estimate: 1_006_000}}, 0.005)
	if len(res.Mismatches) != 1 {
		t.Fatalf("0.6%% off should fail a 0.5%% tolerance: %+v", res)
	}
}

func TestBindParameters(t *testing.T) {
	stop := time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC)
	cases := map[string]string{
		"SELECT count(*) FROM invoices WHERE created_at < :backup_stop_time": "SELECT count(*) FROM invoices WHERE created_at < '2026-11-01T02:00:00Z'::timestamptz",
		"SELECT ':backup_stop_time'":                                         "SELECT ':backup_stop_time'",
		"SELECT x::backup_stop_time":                                         "SELECT x::backup_stop_time",
		"SELECT :backup_stop_times":                                          "SELECT :backup_stop_times",
		"SELECT :backup_stop_lsn":                                            "SELECT '0/5000060'::pg_lsn",
	}
	for in, want := range cases {
		if got := BindParameters(in, stop, "0/5000060"); got != want {
			t.Errorf("%s:\n got %s\nwant %s", in, got, want)
		}
	}
}

func TestValueKeepsOnlyNumbersInClear(t *testing.T) {
	if v := NewValue("12345"); v.Number != "12345" || v.String() != "12345" {
		t.Errorf("%+v", v)
	}
	v := NewValue("alice@example.com")
	if v.Number != "" || strings.Contains(v.String(), "alice") || v.Hash == "" {
		t.Errorf("non-numeric value kept in the clear: %+v", v)
	}
	if !v.Equal(NewValue("alice@example.com")) || v.Equal(NewValue("bob@example.com")) {
		t.Error("hash comparison is wrong")
	}
}

func TestSaveAndLoadLinksToBackup(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Load(dir, "d", "x"); !errors.Is(err, ErrNone) {
		t.Fatalf("got %v", err)
	}
	base := time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC)
	for i, label := range []string{"backup-a", "backup-b", "backup-c"} {
		s := &Snapshot{Drill: "d", BackupLabel: label, CapturedAt: base.Add(time.Duration(i) * time.Hour)}
		if _, err := Save(dir, s); err != nil {
			t.Fatal(err)
		}
	}
	s, exact, err := Load(dir, "d", "backup-b")
	if err != nil || !exact || s.BackupLabel != "backup-b" {
		t.Fatalf("%v %v %+v", err, exact, s)
	}
	s, exact, err = Load(dir, "d", "backup-z")
	if err != nil || exact || s.BackupLabel != "backup-c" {
		t.Fatalf("fallback should be the newest, not exact: %v %v %+v", err, exact, s)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "d", "*.json"))
	if len(matches) != 3 {
		t.Fatalf("files = %v", matches)
	}
}

func TestTLSNote(t *testing.T) {
	cases := map[string]bool{
		"postgres://u:p@db.example.com/x?sslmode=verify-full": false,
		"postgres://u:p@db.example.com/x?sslmode=verify-ca":   false,
		"postgres://u:p@db.example.com/x":                     true,
		"postgres://u:p@db.example.com/x?sslmode=require":     true,
		"postgres://u:p@db.example.com/x?sslmode=disable":     true,
		"postgres://u:p@127.0.0.1/x?sslmode=disable":          false,
		"host=/var/run/postgresql dbname=x":                   false,
	}
	for dsn, want := range cases {
		if got := TLSNote(dsn) != ""; got != want {
			t.Errorf("%s: note=%v", dsn, got)
		}
	}
}
