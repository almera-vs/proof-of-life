package pgbackrest

import (
	"bufio"
	"cmp"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	segmentFile = regexp.MustCompile(`(?:^|/)([0-9A-F]{24})-[0-9a-f]{40}(?:\.[a-z0-9]+)?$`)
	historyFile = regexp.MustCompile(`(?:^|/)([0-9A-F]{8})\.history(?:\.[a-z0-9]+)?$`)
)

type segment struct {
	tli uint32
	num uint64
}

func parseSegment(name string, walSize int64) (segment, error) {
	if len(name) != 24 {
		return segment{}, fmt.Errorf("invalid WAL segment name %q", name)
	}
	tli, err1 := strconv.ParseUint(name[:8], 16, 32)
	log, err2 := strconv.ParseUint(name[8:16], 16, 32)
	seg, err3 := strconv.ParseUint(name[16:], 16, 32)
	if err1 != nil || err2 != nil || err3 != nil {
		return segment{}, fmt.Errorf("invalid WAL segment name %q", name)
	}
	return segment{tli: uint32(tli), num: log*segmentsPerLog(walSize) + seg}, nil
}

func segmentsPerLog(walSize int64) uint64 { return (1 << 32) / uint64(walSize) }

func (s segment) name(walSize int64) string {
	per := segmentsPerLog(walSize)
	return fmt.Sprintf("%08X%08X%08X", s.tli, s.num/per, s.num%per)
}

func (s segment) startLSN(walSize int64) string {
	pos := s.num * uint64(walSize)
	return fmt.Sprintf("%X/%X", pos>>32, pos&0xffffffff)
}

type switchPoint struct {
	parent uint32
	lsn    uint64
}

func parseHistory(text string) ([]switchPoint, error) {
	var out []switchPoint
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return nil, fmt.Errorf("invalid timeline history line %q", line)
		}
		tli, err := strconv.ParseUint(f[0], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid timeline history line %q", line)
		}
		lsn, err := parseLSN(f[1])
		if err != nil {
			return nil, err
		}
		out = append(out, switchPoint{parent: uint32(tli), lsn: lsn})
	}
	return out, nil
}

func parseLSN(s string) (uint64, error) {
	hi, lo, ok := strings.Cut(s, "/")
	if !ok {
		return 0, fmt.Errorf("invalid LSN %q", s)
	}
	h, err1 := strconv.ParseUint(hi, 16, 32)
	l, err2 := strconv.ParseUint(lo, 16, 32)
	if err1 != nil || err2 != nil {
		return 0, fmt.Errorf("invalid LSN %q", s)
	}
	return h<<32 | l, nil
}

type listing struct {
	segments  map[uint32]map[uint64]bool
	histories []uint32
}

func parseListing(data []byte, walSize int64) (listing, error) {
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		return listing{}, fmt.Errorf("parse archive listing: %w", err)
	}
	l := listing{segments: map[uint32]map[uint64]bool{}}
	for path := range entries {
		if m := segmentFile.FindStringSubmatch(path); m != nil {
			s, err := parseSegment(m[1], walSize)
			if err != nil {
				return listing{}, err
			}
			if l.segments[s.tli] == nil {
				l.segments[s.tli] = map[uint64]bool{}
			}
			l.segments[s.tli][s.num] = true
		}
		if m := historyFile.FindStringSubmatch(path); m != nil {
			tli, err := strconv.ParseUint(m[1], 16, 32)
			if err != nil {
				return listing{}, fmt.Errorf("invalid history file name %q", path)
			}
			l.histories = append(l.histories, uint32(tli))
		}
	}
	slices.Sort(l.histories)
	return l, nil
}

type plan struct {
	Needed  []string
	Missing []string

	Histories []string

	Last segment
}

type stretch struct {
	tli       uint32
	endBefore uint64
}

func timelinePath(start uint32, target uint32, histories map[uint32][]switchPoint, walSize int64) ([]stretch, error) {
	if target == start {
		return []stretch{{tli: start}}, nil
	}
	points, ok := histories[target]
	if !ok {
		return nil, fmt.Errorf("the history file for timeline %d is missing from the archive", target)
	}

	var out []stretch
	seenStart := false
	for _, p := range points {
		if p.parent == start {
			seenStart = true
		}
		if seenStart {
			out = append(out, stretch{tli: p.parent, endBefore: p.lsn / uint64(walSize)})
		}
	}
	if !seenStart {
		return nil, fmt.Errorf("timeline %d does not descend from the backup's timeline %d", target, start)
	}
	return append(out, stretch{tli: target}), nil
}

func bestTarget(start uint32, histories map[uint32][]switchPoint) uint32 {
	best := start
	for tli, points := range histories {
		if tli <= best {
			continue
		}
		for _, p := range points {
			if p.parent == start {
				best = tli
				break
			}
		}
	}
	return best
}

func buildPlan(l listing, startName, stopName string, histories map[uint32][]switchPoint, walSize int64) (plan, error) {
	start, err := parseSegment(startName, walSize)
	if err != nil {
		return plan{}, err
	}
	stop, err := parseSegment(stopName, walSize)
	if err != nil {
		return plan{}, err
	}
	target := bestTarget(start.tli, histories)
	path, err := timelinePath(start.tli, target, histories, walSize)
	if err != nil {
		return plan{}, err
	}
	var p plan
	cursor := start.num
	for _, st := range path {
		present := l.segments[st.tli]
		end := st.endBefore
		if end == 0 {
			end = cursor
			for n := range present {
				end = max(end, n+1)
			}

			if st.tli == stop.tli {
				end = max(end, stop.num+1)
			}
		}
		for n := cursor; n < end; n++ {
			s := segment{tli: st.tli, num: n}
			if present[n] {
				p.Needed = append(p.Needed, s.name(walSize))
				p.Last = s
			} else {
				p.Missing = append(p.Missing, s.name(walSize))
			}
		}
		cursor = max(cursor, end)
	}
	keys := make([]uint32, 0, len(histories))
	for tli := range histories {
		keys = append(keys, tli)
	}
	slices.SortFunc(keys, cmp.Compare[uint32])
	for _, tli := range keys {
		p.Histories = append(p.Histories, fmt.Sprintf("%08X.history", tli))
	}
	return p, nil
}
