# Adding a BackupSource

A new backup system plugs in behind one interface in `internal/source/source.go`.

```go
type BackupSource interface {
    Latest(ctx context.Context) (BackupRef, error)
    Describe(ctx context.Context, ref BackupRef) (BackupMeta, error)
    Restore(ctx context.Context, ref BackupRef, target RestoreTarget, inst sandbox.Instance) (RestoreResult, error)
    Verify(ctx context.Context, ref BackupRef, inst sandbox.Instance) (VerifyResult, error)
}
```

A source that replays WAL also implements `Recoverer`:

```go
type Recoverer interface {
    Recover(ctx context.Context, ref BackupRef, target RestoreTarget, inst sandbox.Instance) (RecoveryResult, error)
}
```

The presence of `Recoverer` is what makes a source physical: `recovery.wal_continuity` and `recovery.pitr_target` run for it, and are skipped with an explanation otherwise.

`pgdump` is the shortest example of a logical source, and `pgbackrest` of a physical one.

## Steps

1. Create `internal/source/<name>/`.
2. Add its name to `Source*` in `internal/config/config.go`, its fields to `config.Source`, and its rules to `validateSource`. Errors must name the field.
3. Add a case to `newSource` in `cmd/pol/run.go`.
4. Implement the methods as described below.
5. Add a compatibility rule to `tooling.version_drift` in `internal/checks/integrity.go`, using facts from the tool's own release notes.
6. Add integration tests in `test/integration` and every applicable fault in `test/fault`. A source is not done until its faults produce a failure from the correct check.
7. Remove the source from `docs/roadmap.md`.

## What each method must do

**`Latest`** finds the newest backup. An empty repository is a backup problem, so return a `source.Failure` with kind `FailBackup`. An unreachable repository is an environment problem, so return a plain error.

**`Describe`** fills in `BackupMeta`. `PGMajor` selects the sandbox image, so it must be right. If only part of the metadata can be read, return what you have along with the failure, so that the freshness and version checks can still report something true.

**`Restore`** gets the data onto the sandbox's volume. Use `inst.RunJob` for tools, with `Network: "restore"` only on jobs that need object storage, and `inst.CopyIn` to stream files in. The server gets no network, so a logical source starts it here with `inst.StartServer` and a physical source starts it in `Recover`.

**`Recover`** replays to `target.Recovery`. Report segment counts, every missing or unreadable segment, and the server's fatal message in `RecoveryResult`, including when you also return an error.

**`Verify`** checks the backup without restoring it. It runs after the timed phases, so it does not count against RTO.

## Rules that keep a false pass out

- **Never trust an exit code you have not tested.** `pgbackrest verify` exits 0 when it finds corruption. Run the tool against real damage and see what it actually does.
- **Unrecognised output is a failure.** If a verdict line is missing, return not OK.
- **Use `source.Failure` for anything wrong with the backup.** A plain error becomes an infrastructure error, exit code 4, "not proven".
- **Do not put row data in a reason.** Tool errors can quote rows, so reduce them to a table name or a count.
- **Check that the server reached the point it claims.** A server that started is not proof that it replayed everything.

## Adding a Check

Add a `simple{...}` value in `internal/checks`, and add it to `All()` in report order. Give it a stable ID, a severity, control references with wording sourced in `docs/controls.md`, and a plain-English reason for anything other than a pass. A check returns `skip` only when it truly cannot apply, or a step it depends on did not happen, and it says which.
