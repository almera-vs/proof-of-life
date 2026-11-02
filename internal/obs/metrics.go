package obs

import (
	"fmt"
	"strings"
	"time"
)

type Metrics struct {
	Drill         string
	Status        string
	RTOSeconds    float64
	RTOReached    bool
	TargetSeconds float64
	BackupAge     float64
	Finished      time.Time
	Passed        int
	Warned        int
	Failed        int
	Skipped       int
}

func WriteTextfile(path string, m Metrics) error {
	label := fmt.Sprintf(`drill=%q`, m.Drill)
	var b strings.Builder
	metric := func(name, help string, value float64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s{%s} %g\n", name, help, name, name, label, value)
	}
	status := func(s string) float64 {
		if m.Status == s {
			return 1
		}
		return 0
	}
	fmt.Fprintf(&b, "# HELP pol_drill_status Outcome of the last drill.\n# TYPE pol_drill_status gauge\n")
	for _, s := range []string{"pass", "warn", "fail"} {
		fmt.Fprintf(&b, "pol_drill_status{%s,status=%q} %g\n", label, s, status(s))
	}
	metric("pol_drill_finished_timestamp_seconds", "When the last drill finished.", float64(m.Finished.Unix()))
	if m.RTOReached {
		metric("pol_rto_seconds", "Measured recovery time of the last drill.", m.RTOSeconds)
	}
	metric("pol_rto_target_seconds", "Configured recovery time objective.", m.TargetSeconds)
	metric("pol_backup_age_seconds", "Age of the drilled backup when the drill began.", m.BackupAge)
	fmt.Fprintf(&b, "# HELP pol_checks Check outcomes of the last drill.\n# TYPE pol_checks gauge\n")
	for s, n := range map[string]int{"pass": m.Passed, "warn": m.Warned, "fail": m.Failed, "skipped": m.Skipped} {
		fmt.Fprintf(&b, "pol_checks{%s,status=%q} %d\n", label, s, n)
	}
	if err := ReplaceFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write metrics: %w", err)
	}
	return nil
}

func FormatShortAge(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
}
