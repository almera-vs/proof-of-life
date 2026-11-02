package sandbox

import (
	"context"
	"io"
)

const (
	LabelRunID   = "pol.run_id"
	LabelSandbox = "pol.sandbox"
	LabelPID     = "pol.pid"
	LabelHost    = "pol.host"
	LabelKeep    = "pol.keep"
)

const (
	DataMount  = "/var/lib/postgresql"
	PGData     = DataMount + "/pol-data"
	WALDir     = DataMount + "/pol-wal"
	ArchiveDir = DataMount + "/pol-archive"
	SocketDir  = "/run/postgresql"
)

type Sandbox interface {
	Create(ctx context.Context, spec Spec) (Instance, error)

	Destroy(ctx context.Context, id string) error
}

type ImagePreparer interface {
	EnsureImage(ctx context.Context, ref string, dockerfile []byte) error
}

type Spec struct {
	RunID       string
	PGMajor     int
	Image       string
	CPUs        float64
	MemoryBytes int64

	Dockerfile []byte
}

type Instance interface {
	ID() string

	RunJob(ctx context.Context, job Job) (ExecResult, error)

	CopyIn(ctx context.Context, dir string, tarStream io.Reader) error

	StartServer(ctx context.Context, args []string) error

	Exec(ctx context.Context, argv []string, env []string) (ExecResult, error)

	ServerRunning(ctx context.Context) (bool, error)

	ServerLogs(ctx context.Context) (string, error)
}

type Job struct {
	Image   string
	Cmd     []string
	Env     []string
	Network string

	Binds []string

	Groups []string
}

type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}
