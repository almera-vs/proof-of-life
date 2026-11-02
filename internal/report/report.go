package report

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/almera-vs/proof-of-life/internal/checks"
	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/drill"
	"github.com/almera-vs/proof-of-life/internal/evidence"
	"github.com/almera-vs/proof-of-life/internal/obs"
)

const SchemaVersion = 1

type Report struct {
	SchemaVersion  int       `json:"schema_version"`
	RunID          string    `json:"run_id"`
	Drill          string    `json:"drill"`
	Status         string    `json:"status"`
	Title          string    `json:"title"`
	Badge          string    `json:"badge"`
	Summary        string    `json:"summary"`
	StartedAt      time.Time `json:"started_at"`
	FinishedAt     time.Time `json:"finished_at"`
	Counts         Counts    `json:"counts"`
	RTO            RTO       `json:"rto"`
	RecoveryPoint  Point     `json:"recovery_point"`
	Backup         Backup    `json:"backup"`
	Phases         []Phase   `json:"phases"`
	Checks         []Check   `json:"checks"`
	Attention      []Check   `json:"attention,omitempty"`
	Controls       []Control `json:"controls"`
	Evidence       Evidence  `json:"evidence"`
	Environment    []KV      `json:"environment"`
	Infrastructure string    `json:"infrastructure_error,omitempty"`
}

type Counts struct {
	Passed   int `json:"passed"`
	Warnings int `json:"warnings"`
	Failed   int `json:"failed"`
	Skipped  int `json:"skipped"`
	Total    int `json:"total"`
}

type RTO struct {
	Reached       bool    `json:"reached"`
	Seconds       float64 `json:"seconds,omitempty"`
	TargetSeconds float64 `json:"target_seconds"`
	Percent       int     `json:"percent,omitempty"`
	Text          string  `json:"text"`
	TargetText    string  `json:"target_text"`
}

type Point struct {
	Time   *time.Time `json:"time,omitempty"`
	LSN    string     `json:"lsn,omitempty"`
	Text   string     `json:"text"`
	Detail string     `json:"detail"`
}

type Backup struct {
	Label       string     `json:"label,omitempty"`
	Tool        string     `json:"tool,omitempty"`
	ToolVersion string     `json:"tool_version,omitempty"`
	PGMajor     int        `json:"pg_major,omitempty"`
	StopTime    *time.Time `json:"stop_time,omitempty"`
	SizeBytes   int64      `json:"size_bytes,omitempty"`
	AgeSeconds  float64    `json:"age_seconds,omitempty"`
	AgeText     string     `json:"age_text"`
	Detail      string     `json:"detail"`
}

type Phase struct {
	Name    string  `json:"name"`
	Label   string  `json:"label"`
	Seconds float64 `json:"seconds"`
	Text    string  `json:"text"`
	Color   string  `json:"-"`
}

type Check struct {
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Severity string   `json:"severity"`
	Proves   string   `json:"proves"`
	Observed string   `json:"observed"`
	Reason   string   `json:"reason,omitempty"`
	Controls []string `json:"controls"`
	Seconds  float64  `json:"seconds"`
	Data     any      `json:"data,omitempty"`
}

type Control struct {
	Name        string   `json:"name"`
	Expectation string   `json:"expectation"`
	SupportedBy []string `json:"supported_by"`
	ByText      string   `json:"by_text"`
	Status      string   `json:"status"`
}

type Evidence struct {
	Written  bool   `json:"written"`
	Seq      uint64 `json:"seq,omitempty"`
	Hash     string `json:"hash,omitempty"`
	PrevHash string `json:"prev_hash,omitempty"`
	KeyID    string `json:"key_id,omitempty"`
	Log      string `json:"log"`

	Note  string `json:"note,omitempty"`
	Error string `json:"error,omitempty"`
}

type KV struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

var controlText = []struct {
	ref         checks.ControlRef
	expectation string
}{
	{checks.DORA, "Periodic testing of backup, restoration and recovery procedures"},
	{checks.ISO, "Backup copies maintained and regularly tested"},
	{checks.SOC2, "Recovery plan procedures are tested"},
	{checks.NIS2, "Backup management and disaster recovery"},
}

var phaseGroups = []struct {
	label, color string
	phases       []string
}{
	{"Select backup", "#9A9D98", []string{drill.PhaseSelect, drill.PhaseDescribe}},
	{"Provision sandbox", "#6F7370", []string{drill.PhaseProvision}},
	{"Restore", "#17191B", []string{drill.PhaseRestore}},
	{"Recover to target", "#E3CF3F", []string{drill.PhaseRecover}},
	{"Start & promote", "#4A4E4B", []string{drill.PhaseStart}},
}

func Build(cfg *config.Config, res *drill.Result, ev Evidence) *Report {
	r := &Report{
		SchemaVersion: SchemaVersion, RunID: res.RunID, Drill: res.Drill, Status: string(res.Verdict),
		StartedAt: res.Started, FinishedAt: res.Finished, Evidence: ev,
	}
	if r.FinishedAt.IsZero() {
		r.FinishedAt = time.Now().UTC()
	}
	if res.InfraErr != nil {
		r.Infrastructure = res.InfraErr.Error()
	}
	r.buildChecks(res)
	r.buildRTO(cfg, res)
	r.buildBackup(res)
	r.buildPoint(res)
	r.buildPhases(res)
	r.buildControls(res)
	r.buildEnvironment(cfg, res)
	r.buildHeadline(res)
	return r
}

func (r *Report) buildChecks(res *drill.Result) {
	for _, c := range res.Checks {
		controls := make([]string, 0, len(c.Controls))
		for _, ref := range c.Controls {
			controls = append(controls, string(ref))
		}
		rc := Check{
			ID: c.ID, Status: string(c.Status), Severity: string(c.Severity), Proves: c.Proves,
			Observed: c.Observed, Reason: c.Reason, Controls: controls, Seconds: c.Seconds, Data: c.Data,
		}
		r.Checks = append(r.Checks, rc)
		r.Counts.Total++
		switch c.Status {
		case checks.Pass:
			r.Counts.Passed++
		case checks.Warn:
			r.Counts.Warnings++
			r.Attention = append(r.Attention, rc)
		case checks.Fail:
			r.Counts.Failed++
			r.Attention = append(r.Attention, rc)
		case checks.Skipped:
			r.Counts.Skipped++
		}
	}
}

func (r *Report) buildRTO(cfg *config.Config, res *drill.Result) {
	target := cfg.Drill.RTOTarget.D()
	r.RTO = RTO{Reached: res.RTOReached, TargetSeconds: target.Seconds(), TargetText: obs.FormatShort(target), Text: "Not reached"}
	if res.RTOReached {
		r.RTO.Seconds = res.RTO.Seconds()
		r.RTO.Text = obs.FormatDuration(res.RTO)
		r.RTO.Percent = int(res.RTO.Seconds() / target.Seconds() * 100)
	}
}

func (r *Report) buildBackup(res *drill.Result) {
	r.Backup.AgeText, r.Backup.Detail = "Unknown", "No backup could be read"
	m := res.Meta
	if m == nil {
		return
	}
	r.Backup.Label, r.Backup.Tool, r.Backup.ToolVersion = m.Label, m.Tool, firstField(m.ToolVersion)
	r.Backup.PGMajor, r.Backup.SizeBytes = m.PGMajor, m.SizeBytes
	r.Backup.Detail = m.Label
	if m.SizeBytes > 0 {
		r.Backup.Detail += " · " + obs.FormatBytes(m.SizeBytes)
	}
	if !m.StopTime.IsZero() {
		stop := m.StopTime
		r.Backup.StopTime = &stop
		age := res.Started.Sub(stop)
		r.Backup.AgeSeconds = age.Seconds()
		r.Backup.AgeText = shortAge(age)
	}
}

func shortAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func (r *Report) buildPoint(res *drill.Result) {
	r.RecoveryPoint = Point{Text: "Not reached", Detail: "Recovery did not finish"}
	if res.Server == nil {
		return
	}
	s := res.Server
	if s.ReplayLSN != "" {
		r.RecoveryPoint.LSN = s.ReplayLSN
	}
	switch {
	case !s.ReplayTime.IsZero():
		t := s.ReplayTime
		r.RecoveryPoint.Time = &t
		r.RecoveryPoint.Text = t.Format("15:04:05")
		r.RecoveryPoint.Detail = "UTC · " + relativeToStop(t, res)
	case res.Meta != nil && !res.Meta.StopTime.IsZero() && res.Meta.Kind == "logical":
		t := res.Meta.StopTime
		r.RecoveryPoint.Time = &t
		r.RecoveryPoint.Text = t.Format("15:04:05")
		r.RecoveryPoint.Detail = "UTC · the moment the archive was taken"
	case s.ReplayLSN != "":
		r.RecoveryPoint.Text = s.ReplayLSN
		r.RecoveryPoint.Detail = "LSN · no transactions after the backup"
	}
}

func relativeToStop(t time.Time, res *drill.Result) string {
	if res.Meta == nil || res.Meta.StopTime.IsZero() {
		return "last replayed transaction"
	}
	d := t.Sub(res.Meta.StopTime).Round(time.Second)
	switch {
	case d < 0:
		return obs.FormatShortAge(-d) + " before backup stop"
	case d == 0:
		return "at backup stop"
	}
	return obs.FormatShortAge(d) + " after backup stop"
}

func (r *Report) buildPhases(res *drill.Result) {
	seconds := map[string]float64{}
	ran := map[string]bool{}
	for _, p := range res.Phases {
		seconds[p.Name] += p.Seconds
		if p.Status != drill.PhaseSkipped {
			ran[p.Name] = true
		}
	}
	for _, g := range phaseGroups {
		total, any := 0.0, false
		for _, name := range g.phases {
			total += seconds[name]
			any = any || ran[name]
		}
		if !any {
			continue
		}
		r.Phases = append(r.Phases, Phase{
			Name: g.phases[0], Label: g.label, Seconds: total, Color: g.color,
			Text: obs.FormatDuration(time.Duration(total * float64(time.Second))),
		})
	}
}

func (r *Report) buildControls(res *drill.Result) {

	proven := 0
	for _, chk := range res.Checks {
		if (chk.ID == "restore.completes" || chk.ID == "server.starts") && chk.Status == checks.Pass {
			proven++
		}
	}
	for _, ct := range controlText {
		c := Control{Name: string(ct.ref), Expectation: ct.expectation}
		failed, warned, passed := false, false, false
		for _, chk := range res.Checks {
			if !slices.Contains(chk.Controls, ct.ref) {
				continue
			}
			c.SupportedBy = append(c.SupportedBy, chk.ID)
			switch chk.Status {
			case checks.Fail:
				failed = true
			case checks.Warn:
				warned = true
			case checks.Pass:
				passed = true
			}
		}
		switch {
		case failed || !passed || proven != 2:
			c.Status = "Not evidenced"
		case warned:
			c.Status = "Partly evidenced"
		default:
			c.Status = "Evidenced"
		}
		c.ByText = strings.Join(c.SupportedBy, " · ")
		if len(c.SupportedBy) == len(res.Checks) && len(res.Checks) > 0 {
			c.ByText = fmt.Sprintf("all %d checks", len(res.Checks))
		}
		r.Controls = append(r.Controls, c)
	}
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return s
}

func (r *Report) buildEnvironment(cfg *config.Config, res *drill.Result) {
	server := "Not started"
	if res.Server != nil {
		server = "PostgreSQL " + res.Server.Version
	}
	r.Environment = []KV{{"Server", server}}
	if res.Meta != nil {
		src := []string{strings.TrimSpace(res.Meta.Tool + " " + firstField(res.Meta.ToolVersion))}
		if cfg.Source.Stanza != "" {
			src = append(src, "stanza "+cfg.Source.Stanza)
		}
		src = append(src, cfg.Source.Repo.Type)
		r.Environment = append(r.Environment, KV{"Source", strings.Join(src, " · ")})
	}
	r.Environment = append(r.Environment,
		KV{"Sandbox", fmt.Sprintf("%s · %g vCPU · %s · network %s", cfg.Sandbox.Runtime, cfg.Sandbox.CPUs, obs.FormatBytes(int64(cfg.Sandbox.Memory)), cfg.Sandbox.Network)},
		KV{"Agent", fmt.Sprintf("pol %s · %s/%s", obs.Version, runtime.GOOS, runtime.GOARCH)},
	)
	if res.FingerprintLabel != "" {
		r.Environment = append(r.Environment, KV{"Reference", "fingerprint of backup " + res.FingerprintLabel})
	}
}

func (r *Report) buildHeadline(res *drill.Result) {
	c := r.Counts
	ran := c.Total - c.Skipped
	backup := "The backup"
	if r.Backup.StopTime != nil {
		backup = "The backup taken at " + r.Backup.StopTime.Format("15:04")
	}
	recovered := ""
	if r.RecoveryPoint.Time != nil {
		recovered = ", recovered to " + r.RecoveryPoint.Time.Format("15:04:05") + " UTC"
	}
	rto := "Measured recovery time was " + spokenDuration(res.RTO) + " against a " + spokenDuration(time.Duration(r.RTO.TargetSeconds*float64(time.Second))) + " target."
	notRun := ""
	if c.Skipped > 0 {
		notRun = fmt.Sprintf(" %d of %d checks did not apply or were not configured.", c.Skipped, c.Total)
	}
	switch {
	case res.InfraErr != nil:
		r.Title, r.Status = "Not proven.", "fail"
		r.Badge = "NOT PROVEN"
		r.Summary = "The drill could not reach a conclusion about this backup, because its own environment failed: " + r.Infrastructure + ". This is not evidence that the backup is good or bad."
	case res.Verdict == drill.VerdictFail:
		r.Title = "Not restorable."
		r.Badge = fmt.Sprintf("FAIL · %d / %d", c.Passed, ran)
		r.Summary = backup + " could not be proven restorable. " + firstReason(r.Attention)
	case res.Verdict == drill.VerdictWarn:
		r.Title = "Restorable, with warnings."
		r.Badge = fmt.Sprintf("WARN · %d / %d", c.Passed, ran)
		r.Summary = backup + " was restored into an isolated sandbox" + recovered + ", and it needs attention: " + firstReason(r.Attention) + " " + rto + notRun
	default:
		r.Title = "Restorable."
		r.Badge = fmt.Sprintf("PASS · %d / %d", c.Passed, ran)
		verb := " and passed every check. "
		if c.Skipped > 0 {
			verb = " and passed every check that ran. "
		}
		r.Summary = backup + " was restored into an isolated sandbox" + recovered + verb + rto + notRun
	}
}

func firstReason(attention []Check) string {
	for _, c := range attention {
		if c.Status == string(checks.Fail) {
			return c.Reason
		}
	}
	if len(attention) > 0 {
		return attention[0].Reason
	}
	return ""
}

func spokenDuration(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	case d%time.Hour == 0:
		return fmt.Sprintf("%d hour", int(d.Hours()))
	case d%time.Minute == 0 && d < time.Hour:
		return fmt.Sprintf("%d minute", int(d.Minutes()))
	case d < time.Hour:
		return fmt.Sprintf("%d minutes %02d seconds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%d hours %02d minutes", int(d.Hours()), int(d.Minutes())%60)
}

//go:embed report.html.tmpl
var htmlSource string

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"phaseBar": func(p Phase) template.CSS {
		return template.CSS(fmt.Sprintf("flex:%.3f 1 0;min-width:6px;background:%s", max(p.Seconds, 0.001), p.Color)) //nolint:gosec
	},
	"swatch": func(p Phase) template.CSS { return template.CSS("background:" + p.Color) }, //nolint:gosec
	"barWidth": func(p int) template.CSS {
		return template.CSS(fmt.Sprintf("width:%d%%", min(p, 100))) //nolint:gosec
	},
	"shortHash": func(h string) string {
		h, ok := strings.CutPrefix(h, "sha256:")
		if !ok || len(h) < 14 {
			return h
		}
		return "sha256:" + h[:6] + "…" + h[len(h)-8:]
	},
	"utc":   func(t time.Time) string { return t.UTC().Format("2 Jan 2006, 15:04") },
	"clock": func(t time.Time) string { return t.UTC().Format("15:04") },
}).Parse(htmlSource))

func (r *Report) HTML() ([]byte, error) {
	var b bytes.Buffer
	if err := htmlTemplate.Execute(&b, r); err != nil {
		return nil, fmt.Errorf("render report: %w", err)
	}
	return b.Bytes(), nil
}

func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode report: %w", err)
	}
	return append(b, '\n'), nil
}

func (r *Report) Write(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create report directory: %w", err)
	}
	j, err := r.JSON()
	if err != nil {
		return "", err
	}
	h, err := r.HTML()
	if err != nil {
		return "", err
	}
	if err := writeAtomic(filepath.Join(dir, r.RunID+".json"), j); err != nil {
		return "", err
	}
	path := filepath.Join(dir, r.RunID+".html")
	return path, writeAtomic(path, h)
}

func writeAtomic(path string, data []byte) error {
	if err := obs.ReplaceFile(path, data, 0o640); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func Load(dir, runID string) (*Report, error) {
	if strings.ContainsAny(runID, `/\`) || runID == "" || runID == "." || runID == ".." {
		return nil, fmt.Errorf("invalid run id %q", runID)
	}
	b, err := os.ReadFile(filepath.Join(dir, runID+".json"))
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	r := &Report{}
	if err := json.Unmarshal(b, r); err != nil {
		return nil, fmt.Errorf("report %s is damaged: %w", runID, err)
	}

	for i := range r.Phases {
		for _, g := range phaseGroups {
			if g.label == r.Phases[i].Label {
				r.Phases[i].Color = g.color
			}
		}
	}
	return r, nil
}

func EvidenceFrom(w evidence.Written, log string) Evidence {
	note := "Signed · chain intact"
	if w.OtherKeys > 0 {
		note = "Signed · links intact, older keys not checked"
	}
	return Evidence{Written: true, Seq: w.Seq, Hash: w.Hash, PrevHash: w.PrevHash, KeyID: w.KeyID, Log: log, Note: note}
}
