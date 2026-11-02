package checks

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/fingerprint"
)

const maxListed = 10

func referenceProblem(env *Env) (CheckResult, bool) {
	if env.Cfg.Fingerprint == nil {
		return skip("No fingerprint section is configured, so there is no reference to compare against."), true
	}
	if env.FingerprintErr != nil {
		if errors.Is(env.FingerprintErr, fingerprint.ErrNone) {
			return fail("no reference", "No fingerprint has been captured for this drill. Run pol fingerprint capture after each backup."), true
		}
		return fail("no reference", "The fingerprint could not be read: "+env.FingerprintErr.Error()), true
	}
	if env.Fingerprint == nil {
		return skip("No backup was selected, so no fingerprint was loaded."), true
	}
	if !env.ServerReady() {
		return skip("The restored server did not start, so there was nothing to compare."), true
	}
	return CheckResult{}, false
}

func referenceNote(env *Env) string {
	if env.FingerprintExact {
		return ""
	}
	return fmt.Sprintf(" The reference was captured for backup %s, not this one.", env.Fingerprint.BackupLabel)
}

func listed(lines []string) string {
	if len(lines) <= maxListed {
		return strings.Join(lines, "; ")
	}
	return strings.Join(lines[:maxListed], "; ") + fmt.Sprintf("; and %d more", len(lines)-maxListed)
}

var schemaFingerprint = simple{
	id:       "schema.fingerprint",
	proves:   "Restored schema matches production",
	severity: Critical,
	controls: []ControlRef{DORA, ISO, NIS2},
	run: func(ctx context.Context, env *Env) CheckResult {
		if r, stop := referenceProblem(env); stop {
			return r
		}
		found, err := fingerprint.ReadSchema(ctx, env.Catalog, env.Database)
		if err != nil {
			return fail("could not read schema", "The restored schema could not be read: "+err.Error())
		}
		hash := fingerprint.Hash(found)
		relations := 0
		for _, o := range found {
			if o.Kind == "relation" {
				relations++
			}
		}
		short := hash[:4] + "…" + hash[len(hash)-4:]
		settingFailures, settingWarnings, err := compareSettings(ctx, env)
		if err != nil {
			return fail("could not read settings", "The restored database's settings could not be read: "+err.Error())
		}
		if hash == env.Fingerprint.SchemaHash && len(settingFailures) == 0 {
			observed := fmt.Sprintf("%d relations · hash %s", relations, short)
			r := pass(observed)
			if len(settingWarnings) > 0 {
				r = warn(observed, listed(settingWarnings)+".")
			}
			r.Data = map[string]any{"schema_hash": hash, "relations": relations}
			return r
		}
		diffs := fingerprint.CompareSchema(env.Fingerprint.Objects, found)
		lines := append([]string{}, settingFailures...)
		for _, d := range diffs {
			lines = append(lines, d.String())
		}
		r := fail(fmt.Sprintf("%d differences · hash %s", len(lines), short),
			"The restored schema does not match production: "+listed(lines)+"."+referenceNote(env))
		r.Data = map[string]any{"schema_hash": hash, "expected_hash": env.Fingerprint.SchemaHash, "diff": diffs}
		return r
	},
}

func compareSettings(ctx context.Context, env *Env) (failures, warnings []string, err error) {
	encoding, collate, ctype, err := fingerprint.ReadSettings(ctx, env.Catalog, env.Database)
	if err != nil {
		return nil, nil, err
	}
	extensions, err := fingerprint.ReadExtensions(ctx, env.Catalog, env.Database)
	if err != nil {
		return nil, nil, err
	}
	failures, warnings = fingerprint.CompareSettings(env.Fingerprint, encoding, collate, ctype, extensions)
	return failures, warnings, nil
}

var dataRowCounts = simple{
	id:       "data.row_counts",
	proves:   "Row counts match within tolerance",
	severity: Critical,
	controls: []ControlRef{ISO, NIS2},
	run: func(ctx context.Context, env *Env) CheckResult {
		if r, stop := referenceProblem(env); stop {
			return r
		}

		if _, err := env.User.Query(ctx, env.Database, "ANALYZE"); err != nil {
			return fail("could not analyze", "The restored tables could not be analyzed: "+err.Error())
		}
		estimates, err := fingerprint.ReadTableCounts(ctx, env.Catalog, env.Database)
		if err != nil {
			return fail("could not read counts", "The restored row estimates could not be read: "+err.Error())
		}
		exact := map[string]int64{}
		for table := range env.Fingerprint.ExactCounts {
			n, err := fingerprint.ExactCount(ctx, env.User, env.Database, table)
			if err != nil {
				continue
			}
			exact[table] = n
		}
		tolerance := env.Cfg.Fingerprint.RowCountTolerance
		res := fingerprint.CompareCounts(env.Fingerprint, exact, estimates, float64(tolerance))
		observed := fmt.Sprintf("%d exact · %d within %s", res.Exact, res.Estimated, tolerance)
		if res.Unknown > 0 {
			observed += fmt.Sprintf(" · %d never analyzed", res.Unknown)
		}
		data := map[string]any{"exact": res.Exact, "estimated": res.Estimated, "never_analyzed": res.Unknown}
		if len(res.Mismatches) == 0 {
			r := pass(observed)
			r.Data = data
			return r
		}
		lines := make([]string, 0, len(res.Mismatches))
		for _, m := range res.Mismatches {
			lines = append(lines, m.String())
		}
		data["mismatches"] = res.Mismatches
		r := fail(fmt.Sprintf("%d tables differ", len(res.Mismatches)),
			"Row counts do not match production: "+listed(lines)+"."+referenceNote(env))
		r.Data = data
		return r
	},
}

func assertionOutcome(ctx context.Context, env *Env, a config.Assertion) (ok bool, problem string) {
	stop, lsn := env.Now, ""
	if env.Meta != nil {
		stop, lsn = env.Meta.StopTime, env.Meta.StopLSN
	}

	if env.Fingerprint != nil {
		stop, lsn = env.Fingerprint.BackupStopTime, env.Fingerprint.BackupStopLSN
	}
	raw, err := fingerprint.SingleValue(ctx, env.User, env.Database, fingerprint.BindParameters(a.SQL, stop, lsn))
	if err != nil {
		return false, fmt.Sprintf("%s: the query failed: %v", a.Name, err)
	}
	found := fingerprint.NewValue(raw)
	var want fingerprint.Value
	if a.Expect.EqualsFingerprint {
		v, present := env.Fingerprint.Assertions[a.Name]
		if !present {
			return false, a.Name + ": the fingerprint holds no value for it; capture a new fingerprint"
		}
		want = v
	} else {
		want = fingerprint.NewValue(*a.Expect.Equals)
	}
	if !found.Equal(want) {
		return false, fmt.Sprintf("%s: expected %s, found %s", a.Name, want, found)
	}
	return true, ""
}

var dataAssertions = simple{
	id:       "data.assertions",
	proves:   "Business assertions return expected values",
	severity: Critical,
	controls: []ControlRef{ISO, NIS2},
	run: func(ctx context.Context, env *Env) CheckResult {
		total := len(env.Cfg.Assertions)
		if total == 0 {
			return skip("No assertions are configured.")
		}
		if env.Cfg.Fingerprint != nil {
			if r, stop := referenceProblem(env); stop {
				return r
			}
		} else if !env.ServerReady() {
			return skip("The restored server did not start, so the assertions could not run.")
		}
		passed := 0
		var problems []string
		for _, a := range env.Cfg.Assertions {
			if ok, problem := assertionOutcome(ctx, env, a); ok {
				passed++
			} else {
				problems = append(problems, problem)
			}
		}
		observed := fmt.Sprintf("%d of %d", passed, total)
		if len(problems) == 0 {
			return pass(observed)
		}
		return fail(observed, "Business assertions did not hold: "+listed(problems)+".")
	},
}
