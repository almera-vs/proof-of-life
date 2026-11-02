package checks

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/almera-vs/proof-of-life/internal/obs"
	"github.com/almera-vs/proof-of-life/internal/sandbox"
	"github.com/almera-vs/proof-of-life/internal/source"
	"github.com/almera-vs/proof-of-life/internal/source/pgbackrest"
)

var backupFreshness = simple{
	id:       "backup.freshness",
	proves:   "Newest backup is within the allowed age",
	severity: Major,
	controls: []ControlRef{ISO, NIS2},
	run: func(_ context.Context, env *Env) CheckResult {
		if env.Meta == nil && env.SelectErr != nil {
			return skip("The backup could not be read, so its age is not known. See backup.integrity.")
		}
		if env.Meta == nil || env.Meta.StopTime.IsZero() {
			return fail("no backup", "No backup with a known completion time was found, so its age cannot be shown.")
		}
		age := env.Now.Sub(env.Meta.StopTime)
		limit := env.Cfg.Drill.MaxAge.D()
		observed := fmt.Sprintf("%s old · max %s", obs.FormatDuration(age), obs.FormatShort(limit))
		if age > limit {
			return fail(observed, fmt.Sprintf("The newest backup finished %s ago, which is older than max_age (%s). The backup job may have stopped running.", obs.FormatDuration(age), obs.FormatShort(limit)))
		}
		return pass(observed)
	},
}

var backupIntegrity = simple{
	id:       "backup.integrity",
	proves:   "Backup verifies clean",
	severity: Critical,
	controls: []ControlRef{ISO, NIS2},
	run: func(ctx context.Context, env *Env) CheckResult {
		if env.SelectErr != nil {
			if f, ok := source.AsFailure(env.SelectErr); ok {
				return fail("unreadable", f.Reason)
			}
			return fail("not read", "The backup could not be read: "+env.SelectErr.Error())
		}
		if env.Meta != nil && env.Meta.PageErrors {
			return fail("page errors", "The backup tool recorded page checksum errors while taking backup "+env.Meta.Label+". The source database may already be corrupt.")
		}
		res, err := env.Source.Verify(ctx, env.Ref, env.Inst)
		if err != nil {
			return fail("not verified", "The backup could not be verified: "+err.Error())
		}
		if !res.OK {
			return fail(res.Summary, "Verification found problems in the backup: "+res.Summary+".")
		}
		return pass(res.Summary)
	},
}

var versionDrift = simple{
	id:       "tooling.version_drift",
	proves:   "Tools are compatible with the server version",
	severity: Critical,
	controls: []ControlRef{NIS2},
	run: func(_ context.Context, env *Env) CheckResult {
		m := env.Meta
		prod := 0
		if env.Fingerprint != nil {
			prod = env.Fingerprint.ServerMajor
		}
		if m == nil {
			return skip("No backup was found, so there are no tool versions to compare.")
		}
		if m.Tool == "pg_dump" {
			return dumpDrift(m, prod)
		}
		return backrestDrift(m, prod)
	},
}

func dumpDrift(m *source.BackupMeta, prod int) CheckResult {
	if m.ToolMajor == 0 {
		if prod != 0 {
			return fail(fmt.Sprintf("no version in archive · server %d", prod), fmt.Sprintf("The archive %s has no readable pg_dump header, so nothing shows it was written by tooling compatible with the PostgreSQL %d server. An older pg_dump refuses to dump a newer server and can leave exactly this behind. Check the pg_dump version on the backup host.", m.Label, prod))
		}
		return fail("no version in archive", fmt.Sprintf("The archive %s has no readable pg_dump header, so the tool that wrote it cannot be identified. An older pg_dump refusing a newer server can leave exactly this behind.", m.Label))
	}
	observed := fmt.Sprintf("client %d = server %d", m.ToolMajor, m.PGMajor)
	if m.ToolMajor < m.PGMajor {
		return fail(fmt.Sprintf("client %d < server %d", m.ToolMajor, m.PGMajor), fmt.Sprintf("This archive was written by pg_dump %d from a PostgreSQL %d server. pg_dump must be at least as new as its server.", m.ToolMajor, m.PGMajor))
	}
	if prod != 0 && m.PGMajor < prod {
		return fail(fmt.Sprintf("backup %d < production %d", m.PGMajor, prod), fmt.Sprintf("Production runs PostgreSQL %d, but the newest archive is from PostgreSQL %d. Backups may have been failing since the upgrade, or an old server is being dumped.", prod, m.PGMajor))
	}
	if m.ToolMajor > m.PGMajor {
		observed = fmt.Sprintf("client %d > server %d", m.ToolMajor, m.PGMajor)
	}
	return pass(observed)
}

func backrestDrift(m *source.BackupMeta, prod int) CheckResult {
	if ok, need := pgbackrest.SupportsMajor(m.ToolVersion, m.PGMajor); !ok {
		return fail("pgBackRest "+m.ToolVersion, fmt.Sprintf("The backup was written by pgBackRest %s, but PostgreSQL %d needs at least %s.", m.ToolVersion, m.PGMajor, need))
	}
	if ok, need := pgbackrest.SupportsMajor(m.RestoreToolVersion, m.PGMajor); !ok {
		return fail("pgBackRest "+m.RestoreToolVersion, fmt.Sprintf("The tool image has pgBackRest %s, but PostgreSQL %d needs at least %s.", m.RestoreToolVersion, m.PGMajor, need))
	}
	if prod != 0 && m.PGMajor != prod {
		return fail(fmt.Sprintf("backup %d ≠ production %d", m.PGMajor, prod), fmt.Sprintf("Production runs PostgreSQL %d, but the newest backup is from PostgreSQL %d. Check that the stanza was upgraded along with the server.", prod, m.PGMajor))
	}
	return pass(fmt.Sprintf("pgBackRest %s · server %d", m.ToolVersion, m.PGMajor))
}

var amcheckCorrupt = regexp.MustCompile(`(?m)^(heap table|btree index) "([^"]+)"`)

var amcheck = simple{
	id:       "integrity.amcheck",
	proves:   "No heap or index corruption found",
	severity: Critical,
	controls: []ControlRef{ISO, NIS2},
	run: func(ctx context.Context, env *Env) CheckResult {
		if !env.Cfg.Checks.Amcheck.Enabled {
			return skip("integrity.amcheck is turned off in the configuration.")
		}
		if !env.ServerReady() {
			return skip("The restored server did not start, so there was nothing to check.")
		}
		budget := env.Cfg.Checks.Amcheck.TimeBudget.D()
		cctx, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		start := time.Now()
		res, err := env.Exec(cctx, []string{
			"pg_amcheck", "-h", sandbox.SocketDir, "-U", env.Superuser, "--all", "--install-missing",
		})
		took := obs.FormatDuration(time.Since(start))
		if err != nil {
			if errors.Is(cctx.Err(), context.DeadlineExceeded) {
				return warn("budget reached · "+took, fmt.Sprintf("pg_amcheck did not finish within its time budget (%s), so part of the database was not checked. It found nothing before stopping. Raise checks.amcheck.time_budget to cover all of it.", obs.FormatShort(budget)))
			}
			return fail("not run", "pg_amcheck could not run: "+err.Error())
		}
		return amcheckResult(res, took)
	},
}

func amcheckResult(res sandbox.ExecResult, took string) CheckResult {
	if res.ExitCode == 0 {
		return pass("heap + btree · " + took)
	}
	seen := map[string]bool{}
	for _, m := range amcheckCorrupt.FindAllStringSubmatch(res.Stdout, -1) {
		seen[m[1]+" "+m[2]] = true
	}
	if len(seen) == 0 {
		return fail(fmt.Sprintf("exit %d", res.ExitCode), fmt.Sprintf("pg_amcheck stopped with exit code %d: %s", res.ExitCode, sandbox.FirstError(res.Stderr)))
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	slices.Sort(names)
	r := fail(fmt.Sprintf("%d relations corrupt", len(names)), "pg_amcheck found corruption in the restored data: "+listed(names)+". The damage came from the backup or from the database it was taken from.")
	r.Data = map[string]any{"corrupt": names}
	return r
}

var rtoWithinTarget = simple{
	id:       "rto.within_target",
	proves:   "Recovery completed within target",
	severity: Major,
	controls: []ControlRef{SOC2, NIS2},
	run: func(_ context.Context, env *Env) CheckResult {
		target := env.Cfg.Drill.RTOTarget.D()
		if !env.RestoreStarted {
			return skip("No restore was attempted, so no recovery time could be measured.")
		}
		if !env.RTOReached {
			return fail("not reached · target "+obs.FormatShort(target), "The database never became ready to serve, so no recovery time could be measured.")
		}
		observed := fmt.Sprintf("%s of %s", obs.FormatDuration(env.RTO), obs.FormatShort(target))
		if env.RTO > target {
			return fail(observed, fmt.Sprintf("Recovery took %s, longer than the %s target. A real recovery from this backup would miss the objective.", obs.FormatDuration(env.RTO), obs.FormatShort(target)))
		}
		return pass(observed)
	},
}
