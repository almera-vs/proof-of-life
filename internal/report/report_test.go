package report

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/almera-vs/proof-of-life/internal/checks"
	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/drill"
	"github.com/almera-vs/proof-of-life/internal/source"
)

func testConfig() *config.Config {
	c := &config.Config{}
	c.Drill.RTOTarget = config.Duration(30 * time.Minute)
	c.Sandbox.Runtime, c.Sandbox.CPUs, c.Sandbox.Memory, c.Sandbox.Network = "docker", 2, 8<<30, "none"
	c.Source.Stanza, c.Source.Repo.Type = "billing", "s3"
	return c
}

func passingResult() *drill.Result {
	stop := time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC)
	start := stop.Add(14 * time.Minute)
	var results []checks.CheckResult
	for _, c := range checks.All() {
		d := c.(checks.Described)
		results = append(results, checks.CheckResult{ID: c.ID(), Status: checks.Pass, Proves: d.Proves(), Severity: d.Severity(), Observed: "ok", Controls: c.Controls()})
	}
	return &drill.Result{
		RunID: "7f3a21", Drill: "billing-prod", Started: start, Finished: start.Add(13 * time.Minute),
		Verdict: drill.VerdictPass, RTOReached: true, RTO: 13*time.Minute + 5*time.Second,
		Meta:   &source.BackupMeta{Label: "20261101-020004F", Tool: "pgBackRest", ToolVersion: "2.54", PGMajor: 17, StopTime: stop, SizeBytes: 412 << 30},
		Server: &checks.ServerFacts{Version: "17.2", Major: 17, ReplayTime: stop.Add(-13 * time.Second), ReplayLSN: "0/5000060"},
		Checks: results,
		Phases: []drill.PhaseTiming{
			{Name: drill.PhaseSelect, Status: drill.PhaseOK, Seconds: 3}, {Name: drill.PhaseDescribe, Status: drill.PhaseOK, Seconds: 2.7},
			{Name: drill.PhaseProvision, Status: drill.PhaseOK, Seconds: 6.1}, {Name: drill.PhaseRestore, Status: drill.PhaseOK, Seconds: 702},
			{Name: drill.PhaseRecover, Status: drill.PhaseOK, Seconds: 68}, {Name: drill.PhaseStart, Status: drill.PhaseOK, Seconds: 3.2},
		},
	}
}

func written() Evidence {
	return Evidence{Written: true, Seq: 42, Hash: "sha256:3f9a0c0000000000000000000000000000000000000000000000000007be1c21d", PrevHash: "sha256:81be5d000000000000000000000000000000000000000000000000000002aa44f0", KeyID: "abc123", Log: "evidence.jsonl", Note: "Signed · chain intact"}
}

func TestPassingReportMatchesDesignWording(t *testing.T) {
	r := Build(testConfig(), passingResult(), written())
	if r.Title != "Restorable." || r.Badge != "PASS · 12 / 12" {
		t.Fatalf("%s %s", r.Title, r.Badge)
	}
	want := "The backup taken at 02:00 was restored into an isolated sandbox, recovered to 01:59:47 UTC and passed every check. Measured recovery time was 13 minutes 05 seconds against a 30 minute target."
	if r.Summary != want {
		t.Fatalf("got:  %s\nwant: %s", r.Summary, want)
	}
	if r.RTO.Text != "13m 05s" || r.RTO.Percent != 43 {
		t.Errorf("%+v", r.RTO)
	}
	if r.RecoveryPoint.Text != "01:59:47" || r.RecoveryPoint.Detail != "UTC · 13s before backup stop" {
		t.Errorf("%+v", r.RecoveryPoint)
	}
	if r.Backup.AgeText != "14m" || r.Backup.Detail != "20261101-020004F · 412 GB" {
		t.Errorf("%+v", r.Backup)
	}
	if len(r.Phases) != 5 || r.Phases[0].Text != "5.7s" || r.Phases[2].Text != "11m 42s" {
		t.Errorf("%+v", r.Phases)
	}
}

func TestSectionOrderFollowsDesign(t *testing.T) {
	r := Build(testConfig(), passingResult(), written())
	h, err := r.HTML()
	if err != nil {
		t.Fatal(err)
	}
	html := string(h)
	last := -1
	for _, s := range []string{"Restore report", "Restorable.", "Measured RTO", "Where the time went", ">Checks<", "Controls evidenced", "Evidence record", "Environment", "No customer data left"} {
		i := strings.Index(html, s)
		if i < 0 {
			t.Fatalf("missing %q", s)
		}
		if i < last {
			t.Fatalf("%q is out of order", s)
		}
		last = i
	}
}

func TestHTMLIsSelfContained(t *testing.T) {
	r := Build(testConfig(), passingResult(), written())
	h, err := r.HTML()
	if err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{`<link\b`, `<script\b`, `src=`, `@import`, `url\(`, `https?://`} {
		if regexp.MustCompile(pattern).Match(h) {
			t.Errorf("found external reference %q", pattern)
		}
	}
	for _, color := range []string{"#F4F3EE", "#17191B", "#E3CF3F", "#2B6A4E", "#B42318"} {
		if !strings.Contains(string(h), color) {
			t.Errorf("palette colour %s is missing", color)
		}
	}
	if !strings.Contains(string(h), "@page{size:A4") {
		t.Error("no A4 print rule")
	}
}

func TestFailingReportLeadsWithTheReason(t *testing.T) {
	res := passingResult()
	res.Verdict = drill.VerdictFail
	res.RTOReached, res.Server = false, nil
	for i := range res.Checks {
		if res.Checks[i].ID == "recovery.wal_continuity" {
			res.Checks[i].Status = checks.Fail
			res.Checks[i].Reason = "The WAL archive has a gap, so the database cannot be recovered to its target."
		}
		if res.Checks[i].ID == "server.starts" {
			res.Checks[i].Status = checks.Skipped
			res.Checks[i].Reason = "The restore did not complete."
		}
	}
	r := Build(testConfig(), res, written())
	if r.Title != "Not restorable." || !strings.HasPrefix(r.Badge, "FAIL") {
		t.Fatalf("%s %s", r.Title, r.Badge)
	}
	if !strings.Contains(r.Summary, "The WAL archive has a gap") {
		t.Fatalf("%s", r.Summary)
	}
	if r.RTO.Text != "Not reached" || r.RecoveryPoint.Text != "Not reached" {
		t.Errorf("%+v %+v", r.RTO, r.RecoveryPoint)
	}
	h, err := r.HTML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(h), "What needs attention") {
		t.Error("no attention section")
	}

	for _, c := range r.Controls {
		if c.Status != "Not evidenced" {
			t.Errorf("a drill with no proven restore must evidence nothing: %+v", c)
		}
	}
}

func TestMissedRTOKeepsOtherControlsEvidenced(t *testing.T) {
	res := passingResult()
	res.Verdict = drill.VerdictFail
	for i := range res.Checks {
		if res.Checks[i].ID == "rto.within_target" {
			res.Checks[i].Status = checks.Fail
		}
	}
	want := map[string]string{
		string(checks.DORA): "Evidenced", string(checks.ISO): "Evidenced",
		string(checks.SOC2): "Not evidenced", string(checks.NIS2): "Not evidenced",
	}
	for _, c := range Build(testConfig(), res, written()).Controls {
		if c.Status != want[c.Name] {
			t.Errorf("%s: %s", c.Name, c.Status)
		}
	}
}

func TestSkippedChecksAreStatedNotHidden(t *testing.T) {
	res := passingResult()
	for i := range res.Checks {
		if res.Checks[i].ID == "data.assertions" {
			res.Checks[i].Status = checks.Skipped
		}
	}
	r := Build(testConfig(), res, written())
	if !strings.Contains(r.Summary, "passed every check that ran") || !strings.Contains(r.Summary, "1 of 12 checks did not apply") {
		t.Fatalf("%s", r.Summary)
	}
	if r.Badge != "PASS · 11 / 11" {
		t.Fatalf("%s", r.Badge)
	}
}

func TestInfrastructureErrorIsNotAClaimAboutTheBackup(t *testing.T) {
	res := passingResult()
	res.Verdict, res.InfraErr = drill.VerdictFail, errors.New("the Docker daemon stopped")
	r := Build(testConfig(), res, written())
	if r.Title != "Not proven." || !strings.Contains(r.Summary, "not evidence") {
		t.Fatalf("%s %s", r.Title, r.Summary)
	}
}

func TestReportEscapesContent(t *testing.T) {
	res := passingResult()
	res.Drill = "<script>alert(1)</script>"
	h, err := Build(testConfig(), res, written()).HTML()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(h), "<script>alert") {
		t.Fatal("drill name was not escaped")
	}
}

func TestMissingEvidenceIsStated(t *testing.T) {
	h, err := Build(testConfig(), passingResult(), Evidence{Log: "e", Error: "the evidence log is damaged"}).HTML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(h), "No signed record exists") || strings.Contains(string(h), "chain intact") {
		t.Fatal("a report must not claim evidence it does not have")
	}
}

func TestWriteAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	r := Build(testConfig(), passingResult(), written())
	path, err := r.Write(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, "7f3a21.html") {
		t.Fatal(path)
	}
	loaded, err := Load(dir, "7f3a21")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Summary != r.Summary || loaded.Phases[2].Color != "#17191B" {
		t.Fatalf("%+v", loaded)
	}
	if _, err := Load(dir, "../etc/passwd"); err == nil {
		t.Fatal("path traversal must be refused")
	}
}
