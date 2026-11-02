package fingerprint

import (
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
)

const (
	ChangeMissing = "missing"
	ChangeExtra   = "extra"
	ChangeChanged = "changed"
)

type Diff struct {
	Change   string `json:"change"`
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
	Expected string `json:"expected,omitempty"`
	Found    string `json:"found,omitempty"`
}

var opaqueKinds = map[string]bool{"function": true, "relation": true, "trigger": true}

func (d Diff) String() string {
	switch d.Change {
	case ChangeMissing:
		return fmt.Sprintf("%s %s is in production but missing from the restored database", d.Kind, d.Identity)
	case ChangeExtra:
		return fmt.Sprintf("%s %s is in the restored database but not in production", d.Kind, d.Identity)
	}
	if opaqueKinds[d.Kind] {
		return fmt.Sprintf("%s %s has a different definition", d.Kind, d.Identity)
	}
	return fmt.Sprintf("%s %s differs: expected %q, found %q", d.Kind, d.Identity, d.Expected, d.Found)
}

func CompareSchema(expected, found []Object) []Diff {
	key := func(o Object) string { return o.Kind + "\x00" + o.Identity }
	want := map[string]Object{}
	for _, o := range expected {
		want[key(o)] = o
	}
	got := map[string]Object{}
	for _, o := range found {
		got[key(o)] = o
	}
	var out []Diff
	for _, k := range slices.Sorted(maps.Keys(want)) {
		e := want[k]
		g, ok := got[k]
		switch {
		case !ok:
			out = append(out, Diff{Change: ChangeMissing, Kind: e.Kind, Identity: e.Identity})
		case normalizeDefinition(e.Definition) != normalizeDefinition(g.Definition):
			d := Diff{Change: ChangeChanged, Kind: e.Kind, Identity: e.Identity}
			if !opaqueKinds[e.Kind] {
				d.Expected, d.Found = e.Definition, g.Definition
			}
			out = append(out, d)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[k]; !ok {
			g := got[k]
			out = append(out, Diff{Change: ChangeExtra, Kind: g.Kind, Identity: g.Identity})
		}
	}
	return out
}

func CompareSettings(snap *Snapshot, encoding, collate, ctype string, extensions map[string]string) (failures, warnings []string) {
	check := func(name, want, got string) {
		if want != got {
			failures = append(failures, fmt.Sprintf("%s is %q in the restored database, but %q in production", name, got, want))
		}
	}
	check("the encoding", snap.Encoding, encoding)
	check("the collation", snap.Collate, collate)
	check("the character type", snap.Ctype, ctype)
	for _, name := range slices.Sorted(maps.Keys(snap.Extensions)) {
		got, ok := extensions[name]
		switch {
		case !ok:
			failures = append(failures, fmt.Sprintf("extension %s is in production but missing from the restored database", name))
		case got != snap.Extensions[name]:
			warnings = append(warnings, fmt.Sprintf("extension %s is version %s in the restored database, but %s in production", name, got, snap.Extensions[name]))
		}
	}
	return failures, warnings
}

type CountMismatch struct {
	Table     string `json:"table"`
	Exact     bool   `json:"exact"`
	Expected  int64  `json:"expected"`
	Found     int64  `json:"found"`
	Tolerance int64  `json:"tolerance"`
}

func (m CountMismatch) String() string {
	if m.Exact {
		return fmt.Sprintf("%s: expected exactly %d rows, found %d", m.Table, m.Expected, m.Found)
	}
	return fmt.Sprintf("%s: expected about %d rows, found %d, tolerance ±%d", m.Table, m.Expected, m.Found, m.Tolerance)
}

const estimateFloor = 10

func EstimateTolerance(t TableCount, fraction float64) int64 {
	return int64(math.Ceil(float64(t.Estimate)*fraction)) + t.Modified + estimateFloor
}

type CountResult struct {
	Exact      int             `json:"exact"`
	Estimated  int             `json:"estimated"`
	Unknown    int             `json:"never_analyzed"`
	Mismatches []CountMismatch `json:"mismatches,omitempty"`
}

func CompareCounts(snap *Snapshot, foundExact map[string]int64, foundEstimates []TableCount, fraction float64) CountResult {
	var res CountResult
	for _, table := range slices.Sorted(maps.Keys(snap.ExactCounts)) {
		want := snap.ExactCounts[table]
		res.Exact++
		got, ok := foundExact[table]
		if !ok || got != want {
			res.Mismatches = append(res.Mismatches, CountMismatch{Table: table, Exact: true, Expected: want, Found: got})
		}
	}
	found := map[string]int64{}
	for _, t := range foundEstimates {
		found[t.Table] = t.Estimate
	}
	for _, t := range snap.Tables {
		if _, isExact := snap.ExactCounts[strings.ReplaceAll(t.Table, `"`, "")]; isExact {
			continue
		}
		if t.Estimate < 0 {
			res.Unknown++
			continue
		}
		res.Estimated++
		got := found[t.Table]
		tol := EstimateTolerance(t, fraction)
		if got < t.Estimate-tol || got > t.Estimate+tol {
			res.Mismatches = append(res.Mismatches, CountMismatch{Table: t.Table, Expected: t.Estimate, Found: got, Tolerance: tol})
		}
	}
	return res
}
