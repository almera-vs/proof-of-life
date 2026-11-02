package checks

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/almera-vs/proof-of-life/internal/fingerprint"
	"github.com/almera-vs/proof-of-life/internal/source"
)

const heartbeatGrace = 5 * time.Second

func isLogical(env *Env) bool {
	_, physical := env.Source.(source.Recoverer)
	return !physical
}

var walContinuity = simple{
	id:       "recovery.wal_continuity",
	proves:   "Every WAL segment to the target is present",
	severity: Critical,
	controls: []ControlRef{DORA, NIS2},
	run: func(_ context.Context, env *Env) CheckResult {
		if isLogical(env) {
			return skip("A pg_dump archive is a single point in time and has no WAL to replay.")
		}
		rec := env.Recovery
		if rec == nil {
			return skip("The restore did not complete, so WAL recovery was not attempted.")
		}
		if rec.SegmentsNeeded == 0 && env.RecoveryErr != nil {
			if f, ok := source.AsFailure(env.RecoveryErr); ok {
				return fail("archive unusable", f.Reason)
			}
			return fail("archive not read", "The WAL archive could not be read: "+env.RecoveryErr.Error())
		}
		data := map[string]any{"segments_needed": rec.SegmentsNeeded, "segments_fetched": rec.SegmentsFetched, "segments_replayed": rec.SegmentsReplayed}
		bad := append(append([]string{}, rec.Missing...), rec.Unreadable...)
		if len(bad) > 0 {
			data["missing"], data["unreadable"] = rec.Missing, rec.Unreadable
			return gapResult(env, rec, data)
		}

		if rec.ServerFatal != "" && !strings.Contains(rec.ServerFatal, "recovery target") {
			r := fail(fmt.Sprintf("%d segments · replay failed", rec.SegmentsNeeded), "WAL replay stopped the server: "+rec.ServerFatal+".")
			r.Data = data
			return r
		}

		if env.Target.Latest && env.ServerReady() && rec.LastSegmentLSN != "" {
			if lsnLess(env.Server.ReplayLSN, rec.LastSegmentLSN) {
				r := fail("replay stopped early", fmt.Sprintf("Replay stopped at %s, before the newest archived segment %s, which starts at %s. WAL after that point was not applied.", env.Server.ReplayLSN, rec.LastSegment, rec.LastSegmentLSN))
				r.Data = data
				return r
			}
		}
		r := pass(fmt.Sprintf("%d segments · %d replayed", rec.SegmentsNeeded, rec.SegmentsReplayed))
		r.Data = data
		return r
	},
}

func gapResult(env *Env, rec *source.RecoveryResult, data map[string]any) CheckResult {
	names := append(append([]string{}, rec.Missing...), rec.Unreadable...)
	shown := names
	suffix := ""
	if len(shown) > 5 {
		shown, suffix = shown[:5], fmt.Sprintf(" and %d more", len(names)-5)
	}
	list := strings.Join(shown, ", ") + suffix
	if !env.Target.Latest && env.ServerReady() && rec.ServerFatal == "" {
		r := warn(fmt.Sprintf("%d segments absent past target", len(names)),
			"The requested target was reached, but WAL after it is not usable: "+list+". A recovery to a later point would stop at the gap.")
		r.Data = data
		return r
	}
	r := fail(fmt.Sprintf("%d of %d segments absent", len(names), rec.SegmentsNeeded),
		"The WAL archive, the transaction log that recovery replays on top of a backup, has a gap, so the database cannot be recovered to its target: "+list+" could not be read from the archive.")
	r.Data = data
	return r
}

func lsnLess(a, b string) bool {
	x, ok1 := lsnValue(a)
	y, ok2 := lsnValue(b)
	return !ok1 || !ok2 || x < y
}

func lsnValue(s string) (uint64, bool) {
	hi, lo, ok := strings.Cut(s, "/")
	if !ok {
		return 0, false
	}
	h, err1 := strconv.ParseUint(hi, 16, 32)
	l, err2 := strconv.ParseUint(lo, 16, 32)
	return h<<32 | l, err1 == nil && err2 == nil
}

var pitrTarget = simple{
	id:       "recovery.pitr_target",
	proves:   "Recovery reached the requested point in time",
	severity: Critical,
	controls: []ControlRef{DORA, NIS2},
	run: func(ctx context.Context, env *Env) CheckResult {
		if isLogical(env) {
			return skip("A pg_dump archive restores to the moment it was taken; there is no point in time to choose.")
		}
		if env.Recovery == nil {
			return skip("The restore did not complete, so recovery was not attempted.")
		}
		if env.Recovery.ServerFatal != "" {
			return fail("target not reached", "Recovery stopped before reaching the target: "+env.Recovery.ServerFatal+".")
		}
		if env.RecoveryErr != nil {
			return fail("target not reached", "Recovery did not finish: "+env.RecoveryErr.Error())
		}
		if !env.ServerReady() {
			return skip("The server did not start, so the point reached could not be read.")
		}
		s := env.Server
		var observed string
		switch {
		case !env.Target.Time.IsZero():
			if s.ReplayTime.After(env.Target.Time) {
				return fail(s.ReplayTime.Format(time.RFC3339), fmt.Sprintf("Recovery replayed past the target: the last transaction is from %s, the target was %s.", s.ReplayTime.Format(time.RFC3339), env.Target.Time.Format(time.RFC3339)))
			}
			observed = reached(s)
		case env.Target.LSN != "":
			if lsnLess(s.ReplayLSN, env.Target.LSN) {
				return fail(s.ReplayLSN, fmt.Sprintf("Recovery stopped at %s, before the target %s.", s.ReplayLSN, env.Target.LSN))
			}
			observed = s.ReplayLSN + " reached"
		default:
			if env.Meta != nil && lsnLess(s.ReplayLSN, env.Meta.StopLSN) {
				return fail(s.ReplayLSN, fmt.Sprintf("Recovery stopped at %s, before the end of the backup at %s, so the restored data is not consistent.", s.ReplayLSN, env.Meta.StopLSN))
			}
			observed = reached(s)
		}
		beat, problem := heartbeat(ctx, env)
		if problem != "" {
			return fail(observed, problem)
		}
		return pass(observed + beat)
	},
}

func reached(s *ServerFacts) string {
	if s.ReplayTime.IsZero() {
		return s.ReplayLSN + " reached"
	}
	return s.ReplayTime.Format("15:04:05") + " UTC reached"
}

func heartbeat(ctx context.Context, env *Env) (observed, problem string) {
	if env.Cfg.Fingerprint == nil || !env.Cfg.Fingerprint.Heartbeat.Enabled {
		return "", ""
	}
	t := env.Target.Time
	if t.IsZero() {
		t = env.Server.ReplayTime
	}
	if t.IsZero() {
		return "", "The heartbeat is enabled, but recovery replayed no transactions to compare it with."
	}
	raw, err := fingerprint.SingleValue(ctx, env.User, env.Database,
		`SELECT coalesce((max(ts) AT TIME ZONE 'UTC')::text, '') FROM `+fingerprint.HeartbeatTable)
	if err != nil {
		return "", "The heartbeat is enabled, but it could not be read from the restored database: " + err.Error() + "."
	}
	if raw == "" {
		return "", "The heartbeat is enabled, but the restored table is empty."
	}
	ts, err := time.Parse("2006-01-02 15:04:05.999999", raw)
	if err != nil {
		return "", "The heartbeat value could not be read."
	}
	interval := env.Cfg.Fingerprint.Heartbeat.Interval.D()
	if err := CheckHeartbeat(ts, t, interval); err != nil {
		return "", err.Error()
	}
	return fmt.Sprintf(" · heartbeat Δ %s", t.Sub(ts).Round(time.Second)), ""
}

func CheckHeartbeat(ts, target time.Time, interval time.Duration) error {
	switch {
	case ts.After(target):
		return fmt.Errorf("the newest heartbeat, %s, is later than the recovery point %s, so recovery went past its target", ts.Format(time.RFC3339), target.Format(time.RFC3339))
	case target.Sub(ts) > interval+heartbeatGrace:
		return fmt.Errorf("the newest heartbeat, %s, is %s older than the recovery point %s, more than the %s interval allows; recovery may have fallen short of its target", ts.Format(time.RFC3339), target.Sub(ts).Round(time.Second), target.Format(time.RFC3339), interval)
	}
	return nil
}
