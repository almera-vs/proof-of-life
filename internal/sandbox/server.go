package sandbox

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

func ServerConfig(memoryBytes int64, recovery string) string {
	shared := max(memoryBytes/4/(1<<20), 32)
	var b strings.Builder
	fmt.Fprintf(&b, "listen_addresses = ''\n")
	fmt.Fprintf(&b, "unix_socket_directories = '%s'\n", SocketDir)
	fmt.Fprintf(&b, "shared_buffers = '%dMB'\n", shared)
	b.WriteString("huge_pages = off\nssl = off\narchive_mode = off\nhot_standby = off\n")
	b.WriteString("logging_collector = off\nlog_destination = 'stderr'\nmax_connections = 40\n")
	b.WriteString(recovery)
	return b.String()
}

const MaintenanceDB = "template1"

const HBAConfig = "local all all trust\n"

type Client struct {
	Inst      Instance
	Superuser string

	Options string
}

func (c Client) Query(ctx context.Context, db, sql string) ([][]string, error) {
	var env []string
	if c.Options != "" {
		env = []string{"PGOPTIONS=" + c.Options}
	}
	res, err := c.Inst.Exec(ctx, []string{
		"psql", "-X", "-q", "--csv", "-t", "-v", "ON_ERROR_STOP=1",
		"-h", SocketDir, "-U", c.Superuser, "-d", db, "-c", sql,
	}, env)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("query failed: %s", RedactValues(FirstError(res.Stderr)))
	}
	r := csv.NewReader(strings.NewReader(res.Stdout))
	r.FieldsPerRecord = -1
	var rows [][]string
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			return rows, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parse query output: %w", err)
		}
		rows = append(rows, rec)
	}
}

func (c Client) WaitReady(ctx context.Context) error {
	for {
		running, err := c.Inst.ServerRunning(ctx)
		if err != nil {
			return err
		}
		if !running {
			logs, err := c.Inst.ServerLogs(context.WithoutCancel(ctx))
			if err != nil {
				return err
			}
			return &ServerExitError{Fatal: FatalLine(logs), Logs: logs}
		}
		res, err := c.Inst.Exec(ctx, []string{
			"psql", "-X", "-At", "-h", SocketDir, "-U", c.Superuser, "-d", MaintenanceDB, "-c", "SELECT 1",
		}, nil)
		if err != nil {
			return err
		}
		if res.ExitCode == 0 {
			return nil
		}
		if strings.Contains(res.Stderr, "role \"") && strings.Contains(res.Stderr, "does not exist") {
			return fmt.Errorf("role %q is not in the restored cluster; set sandbox.superuser: %s", c.Superuser, FirstError(res.Stderr))
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for the server to accept connections: %w", ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

type ServerExitError struct {
	Fatal string
	Logs  string
}

func (e *ServerExitError) Error() string {
	if e.Fatal == "" {
		return "the server exited during startup"
	}
	return "the server exited during startup: " + e.Fatal
}

var connectionFatal = []string{"the database system is starting up", "the database system is shutting down", "the database system is not", "the database system is in recovery"}

func FatalLine(logs string) string {
	found := ""
	for line := range strings.SplitSeq(logs, "\n") {
		for _, marker := range []string{"FATAL:", "PANIC:"} {
			_, msg, ok := strings.Cut(line, marker)
			if !ok {
				continue
			}
			msg = strings.TrimSpace(msg)
			if !slices.ContainsFunc(connectionFatal, func(c string) bool { return strings.HasPrefix(msg, c) }) {
				found = msg
			}
		}
	}
	return found
}

func FirstError(s string) string {
	for line := range strings.SplitSeq(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return "no error output"
}
