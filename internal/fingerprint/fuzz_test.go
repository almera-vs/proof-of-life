package fingerprint

import (
	"strings"
	"testing"
	"time"
)

const (
	stopLiteral = "'2026-11-01T02:00:00Z'::timestamptz"
	lsnLiteral  = "'0/5000060'::pg_lsn"
)

func FuzzBindParameters(f *testing.F) {
	f.Add("SELECT count(*) FROM t WHERE created_at < :backup_stop_time")
	f.Add("SELECT ':backup_stop_time', x::backup_stop_time, :backup_stop_lsn")
	f.Add("'unterminated :backup_stop_time")
	f.Fuzz(func(t *testing.T, sql string) {
		if strings.Contains(sql, stopLiteral) || strings.Contains(sql, lsnLiteral) {
			return
		}
		stop := time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC)
		out := BindParameters(sql, stop, "0/5000060")
		back := strings.ReplaceAll(strings.ReplaceAll(out, stopLiteral, ":backup_stop_time"), lsnLiteral, ":backup_stop_lsn")
		if back != sql {
			t.Fatalf("binding changed more than the placeholders:\n in: %q\nout: %q", sql, out)
		}
	})
}
