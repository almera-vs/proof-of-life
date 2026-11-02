//go:build integration

package harness

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (s *Stack) ForkTimeline(target time.Time) {
	s.t.Helper()
	ctx := context.Background()
	const dir = "/tmp/pg2"
	stamp := target.UTC().Format("2006-01-02 15:04:05") + "+00"
	s.Shell(fmt.Sprintf(`mkdir -m 700 %s && pgbackrest restore --pg1-path=%s --type=time --target='%s' --target-action=promote`, dir, dir, stamp))
	conf := fmt.Sprintf("wal_level = replica\narchive_mode = on\narchive_timeout = 2\narchive_command = 'pgbackrest --pg1-path=%s archive-push %%p'\n", dir)
	if err := s.PG.CopyToContainer(ctx, []byte(conf), "/tmp/pg2.conf", 0o644); err != nil {
		s.t.Fatal(err)
	}
	s.Shell(fmt.Sprintf(`cat /tmp/pg2.conf >> %s/postgresql.auto.conf`, dir))
	s.Shell(fmt.Sprintf(`/usr/lib/postgresql/%d/bin/pg_ctl -D %s -l /tmp/pg2.log -o "-p 5433" -w -t 120 start`, s.Major, dir))
	deadline := time.Now().Add(2 * time.Minute)
	for {
		out, code := s.ShellCode(`psql -X -At -p 5433 -d billing -c "SELECT pg_is_in_recovery(), (SELECT timeline_id FROM pg_control_checkpoint())"`)
		if code == 0 && strings.HasPrefix(strings.TrimSpace(out), "f") {
			return
		}
		if time.Now().After(deadline) {
			log, _ := s.ShellCode("tail -20 /tmp/pg2.log")
			s.t.Fatalf("the forked server was not promoted: %s\n%s", out, log)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (s *Stack) SQLOnFork(sql string) {
	s.t.Helper()
	s.Shell(fmt.Sprintf(`psql -X -q -At -v ON_ERROR_STOP=1 -p 5433 -d billing -c "%s"`, sql))
	s.Shell(`psql -X -q -At -p 5433 -d billing -c "SELECT pg_switch_wal()"`)
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		out := s.Shell(`psql -X -At -p 5433 -d billing -c "SELECT count(*) FROM pg_ls_archive_statusdir() WHERE name LIKE '%.ready'"`)
		if strings.TrimSpace(out) == "0" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	s.t.Fatal("the forked server did not archive its WAL")
}
