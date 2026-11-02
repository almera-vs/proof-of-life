package pgbackrest

import (
	"reflect"
	"testing"
)

const wal16MB = 16 << 20

func TestSegmentRoundTrip(t *testing.T) {
	for _, name := range []string{"000000010000000000000003", "0000000300000A2F000000C4", "0000000100000001000000FF"} {
		s, err := parseSegment(name, wal16MB)
		if err != nil {
			t.Fatal(err)
		}
		if got := s.name(wal16MB); got != name {
			t.Errorf("got %s want %s", got, name)
		}
	}
	s, _ := parseSegment("000000010000000000000003", wal16MB)
	if got := s.startLSN(wal16MB); got != "0/3000000" {
		t.Errorf("startLSN = %s", got)
	}
	if _, err := parseSegment("nonsense", wal16MB); err == nil {
		t.Error("expected an error")
	}
}

func TestSegmentCrossesLogBoundary(t *testing.T) {
	a, _ := parseSegment("0000000100000000000000FF", wal16MB)
	b, _ := parseSegment("000000010000000100000000", wal16MB)
	if b.num != a.num+1 {
		t.Fatalf("%d then %d", a.num, b.num)
	}
}

func TestParseListingIgnoresOtherFiles(t *testing.T) {
	data := []byte(`{
	 ".":{"type":"path"},
	 "17-1/0000000100000000":{"type":"path"},
	 "17-1/0000000100000000/000000010000000000000003-be02dd46e3ca8955c8360d736aba238946997a91.gz":{"type":"file"},
	 "17-1/0000000100000000/000000010000000000000003.00000028.backup":{"type":"file"},
	 "17-1/0000000100000000/000000010000000000000004.partial-47f5636ff472f93248c4d5d4430b7a5bae2a3e28.gz":{"type":"file"},
	 "17-1/0000000100000000/000000010000000000000005-47f5636ff472f93248c4d5d4430b7a5bae2a3e28":{"type":"file"},
	 "17-1/00000002.history":{"type":"file"}
	}`)
	l, err := parseListing(data, wal16MB)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.segments[1]) != 2 || !l.segments[1][3] || !l.segments[1][5] {
		t.Fatalf("segments = %v", l.segments)
	}
	if !reflect.DeepEqual(l.histories, []uint32{2}) {
		t.Fatalf("histories = %v", l.histories)
	}
}

func seg(tli uint32, nums ...uint64) map[uint64]bool {
	m := map[uint64]bool{}
	for _, n := range nums {
		m[n] = true
	}
	return m
}

func TestPlanContinuous(t *testing.T) {
	l := listing{segments: map[uint32]map[uint64]bool{1: seg(1, 1, 2, 3, 4, 5)}}
	p, err := buildPlan(l, "000000010000000000000003", "000000010000000000000003", nil, wal16MB)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Missing) != 0 || len(p.Needed) != 3 {
		t.Fatalf("%+v", p)
	}
	if p.Last.name(wal16MB) != "000000010000000000000005" {
		t.Fatalf("last = %s", p.Last.name(wal16MB))
	}
}

func TestPlanFindsGapBeforeNewestSegment(t *testing.T) {
	l := listing{segments: map[uint32]map[uint64]bool{1: seg(1, 3, 4, 6, 7)}}
	p, err := buildPlan(l, "000000010000000000000003", "000000010000000000000003", nil, wal16MB)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Missing, []string{"000000010000000000000005"}) {
		t.Fatalf("missing = %v", p.Missing)
	}
}

func TestPlanMissingBackupStartSegment(t *testing.T) {
	l := listing{segments: map[uint32]map[uint64]bool{1: seg(1, 4, 5)}}
	p, err := buildPlan(l, "000000010000000000000003", "000000010000000000000003", nil, wal16MB)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Missing, []string{"000000010000000000000003"}) {
		t.Fatalf("missing = %v", p.Missing)
	}
}

func TestPlanFollowsTimelineSwitch(t *testing.T) {

	histories := map[uint32][]switchPoint{2: {{parent: 1, lsn: 0x5000100}}}
	l := listing{segments: map[uint32]map[uint64]bool{
		1: seg(1, 3, 4, 5),
		2: seg(2, 5, 6),
	}, histories: []uint32{2}}
	p, err := buildPlan(l, "000000010000000000000003", "000000010000000000000003", histories, wal16MB)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"000000010000000000000003", "000000010000000000000004", "000000020000000000000005", "000000020000000000000006"}
	if !reflect.DeepEqual(p.Needed, want) || len(p.Missing) != 0 {
		t.Fatalf("%+v", p)
	}
	if !reflect.DeepEqual(p.Histories, []string{"00000002.history"}) {
		t.Fatalf("histories = %v", p.Histories)
	}
}

func TestPlanFindsGapAcrossTimelines(t *testing.T) {
	histories := map[uint32][]switchPoint{2: {{parent: 1, lsn: 0x5000100}}}
	l := listing{segments: map[uint32]map[uint64]bool{
		1: seg(1, 3),
		2: seg(2, 5, 6),
	}}
	p, err := buildPlan(l, "000000010000000000000003", "000000010000000000000003", histories, wal16MB)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Missing, []string{"000000010000000000000004"}) {
		t.Fatalf("missing = %v", p.Missing)
	}
}

func TestPlanIgnoresUnrelatedTimeline(t *testing.T) {

	histories := map[uint32][]switchPoint{3: {{parent: 9, lsn: 0x1000000}}}
	l := listing{segments: map[uint32]map[uint64]bool{1: seg(1, 3, 4), 3: seg(3, 8)}}
	p, err := buildPlan(l, "000000010000000000000003", "000000010000000000000003", histories, wal16MB)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Needed) != 2 || len(p.Missing) != 0 {
		t.Fatalf("%+v", p)
	}
}

func TestParseHistory(t *testing.T) {
	got, err := parseHistory("1\t0/5000100\tno recovery target specified\n\n2\t0/9000000\tbefore 2026\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []switchPoint{{parent: 1, lsn: 0x5000100}, {parent: 2, lsn: 0x9000000}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
	if _, err := parseHistory("garbage"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestParseVerify(t *testing.T) {
	ok, summary := parseVerify("stanza: demo\nstatus: ok\n  archiveId: 17-1, total WAL checked: 9, total valid WAL: 9\n  backup: 20261101-185052F, status: valid, total files checked: 972, total valid files: 972\n")
	if !ok || summary != "pgbackrest verify · 972 files · 9 WAL · 0 errors" {
		t.Fatalf("%v %q", ok, summary)
	}
	ok, summary = parseVerify("stanza: demo\nstatus: error\n  backup: 20261101-185052F, status: invalid, total files checked: 972, total valid files: 971\n    missing: 0, checksum invalid: 1, size invalid: 0, other: 0\n")
	if ok {
		t.Fatal("corrupt repository reported as ok")
	}
	if summary != "pgbackrest verify · status error · checksum invalid: 1" {
		t.Fatalf("%q", summary)
	}

	if ok, _ := parseVerify(""); ok {
		t.Fatal("empty output reported as ok")
	}
}

func TestToolSupportsMajor(t *testing.T) {
	cases := []struct {
		tool  string
		major int
		want  bool
	}{
		{"2.60.0", 18, true}, {"2.55.0", 18, true}, {"2.54", 18, false},
		{"2.52", 17, true}, {"2.51", 17, false}, {"2.46", 16, true},
		{"2.39", 15, true}, {"2.34", 14, true}, {"2.33", 14, false},
	}
	for _, c := range cases {
		if got, _ := SupportsMajor(c.tool, c.major); got != c.want {
			t.Errorf("%s on %d: got %v", c.tool, c.major, got)
		}
	}
}

func TestPlanRequiresWALThroughBackupStopEvenWithAnEmptyArchive(t *testing.T) {
	l := listing{segments: map[uint32]map[uint64]bool{}}
	p, err := buildPlan(l, "000000010000000000000003", "000000010000000000000005", nil, wal16MB)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"000000010000000000000003", "000000010000000000000004", "000000010000000000000005"}
	if !reflect.DeepEqual(p.Missing, want) || len(p.Needed) != 0 {
		t.Fatalf("%+v", p)
	}
}
