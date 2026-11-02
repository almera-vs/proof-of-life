package source

import (
	"context"
	"errors"
	"time"

	"github.com/almera-vs/proof-of-life/internal/sandbox"
)

type BackupSource interface {
	Latest(ctx context.Context) (BackupRef, error)
	Describe(ctx context.Context, ref BackupRef) (BackupMeta, error)
	Restore(ctx context.Context, ref BackupRef, target RestoreTarget, inst sandbox.Instance) (RestoreResult, error)

	Verify(ctx context.Context, ref BackupRef, inst sandbox.Instance) (VerifyResult, error)
}

type Recoverer interface {
	Recover(ctx context.Context, ref BackupRef, target RestoreTarget, inst sandbox.Instance) (RecoveryResult, error)
}

type Preparer interface {
	Prepare(ctx context.Context) error
}

type BackupRef struct {
	Label string
}

type BackupMeta struct {
	Label       string `json:"label"`
	Kind        string `json:"kind"`
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version,omitempty"`

	RestoreToolVersion string `json:"restore_tool_version,omitempty"`
	PGMajor            int    `json:"pg_major"`

	ServerVersion string    `json:"server_version,omitempty"`
	StartLSN      string    `json:"start_lsn,omitempty"`
	StopLSN       string    `json:"stop_lsn,omitempty"`
	StartTime     time.Time `json:"start_time,omitzero"`
	StopTime      time.Time `json:"stop_time,omitzero"`
	SizeBytes     int64     `json:"size_bytes,omitempty"`
	RepoBytes     int64     `json:"repo_bytes,omitempty"`
	Database      string    `json:"database,omitempty"`
	Format        string    `json:"format,omitempty"`

	ToolMajor int `json:"tool_major,omitempty"`

	PageErrors bool `json:"page_errors,omitempty"`

	ArchiveStart string `json:"archive_start,omitempty"`
	ArchiveStop  string `json:"archive_stop,omitempty"`
	ArchiveID    string `json:"archive_id,omitempty"`
}

type RecoveryTarget struct {
	Latest bool
	Time   time.Time
	LSN    string
}

type RestoreTarget struct {
	Recovery    RecoveryTarget
	MemoryBytes int64
	CPUs        float64
	Superuser   string
}

type RestoreResult struct {
	Database string
}

type VerifyResult struct {
	Tool    string `json:"tool"`
	OK      bool   `json:"ok"`
	Summary string `json:"summary"`
}

type RecoveryResult struct {
	SegmentsNeeded int `json:"segments_needed"`

	SegmentsFetched int `json:"segments_fetched"`

	SegmentsReplayed int `json:"segments_replayed"`

	Missing []string `json:"missing,omitempty"`

	Unreadable []string `json:"unreadable,omitempty"`

	LastSegmentLSN string `json:"last_segment_lsn,omitempty"`
	LastSegment    string `json:"last_segment,omitempty"`

	ServerFatal string `json:"server_fatal,omitempty"`
}

type FailureKind string

const (
	FailBackup   FailureKind = "backup"
	FailRestore  FailureKind = "restore"
	FailRecovery FailureKind = "recovery"
)

type Failure struct {
	Kind   FailureKind
	Reason string
}

func (f *Failure) Error() string { return f.Reason }

func Failf(kind FailureKind, reason string) *Failure {
	return &Failure{Kind: kind, Reason: reason}
}

func AsFailure(err error) (*Failure, bool) {
	var f *Failure
	if errors.As(err, &f) {
		return f, true
	}
	return nil, false
}
