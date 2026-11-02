package checks

import (
	"context"
	"errors"
	"fmt"

	"github.com/almera-vs/proof-of-life/internal/obs"
	"github.com/almera-vs/proof-of-life/internal/source"
)

var restoreCompletes = simple{
	id:       "restore.completes",
	proves:   "Restore finishes without errors",
	severity: Critical,
	controls: []ControlRef{DORA, ISO, SOC2, NIS2},
	run: func(_ context.Context, env *Env) CheckResult {
		if !env.RestoreStarted {
			switch {
			case env.ProvisionErr != nil:
				return fail("sandbox not provisioned", "The sandbox could not be created, so no restore took place: "+env.ProvisionErr.Error())
			default:
				return skip("No usable backup was found, so no restore was attempted.")
			}
		}
		if env.RestoreErr != nil {
			if errors.Is(env.RestoreErr, context.DeadlineExceeded) {
				return fail("timed out", fmt.Sprintf("The restore did not finish within restore_timeout (%s).", env.Cfg.Drill.RestoreTimeout.D()))
			}
			if f, ok := source.AsFailure(env.RestoreErr); ok {
				return fail("restore failed", f.Reason)
			}
			return fail("restore failed", "The restore could not run: "+env.RestoreErr.Error())
		}
		observed := obs.FormatDuration(env.RestoreTime)
		if env.Meta != nil && env.Meta.SizeBytes > 0 {
			observed += " · " + obs.FormatBytes(env.Meta.SizeBytes)
		}
		return pass(observed)
	},
}

var serverStarts = simple{
	id:       "server.starts",
	proves:   "Server accepts connections after promotion",
	severity: Critical,
	controls: []ControlRef{DORA, NIS2},
	run: func(_ context.Context, env *Env) CheckResult {
		if env.ServerErr != nil {
			return fail("did not start", "The restored server did not start: "+env.ServerErr.Error())
		}
		if env.Server == nil {
			return skip("The restore did not complete, so there was no server to start.")
		}
		s := env.Server
		if s.InRecovery {
			return fail("still in recovery", "The server accepts connections but pg_is_in_recovery() is still true, so it was never promoted.")
		}
		if env.Meta != nil && env.Meta.PGMajor != s.Major {
			return fail("PostgreSQL "+s.Version, fmt.Sprintf("The backup is from PostgreSQL %d, but the server that started is PostgreSQL %d.", env.Meta.PGMajor, s.Major))
		}
		return pass("PostgreSQL " + s.Version + " · accepting connections")
	},
}
