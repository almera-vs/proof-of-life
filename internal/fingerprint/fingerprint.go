package fingerprint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Querier interface {
	Query(ctx context.Context, db, sql string) ([][]string, error)
}

type Object struct {
	Kind       string `json:"kind"`
	Identity   string `json:"identity"`
	Definition string `json:"definition"`
}

type TableCount struct {
	Table string `json:"table"`

	Estimate int64 `json:"estimate"`

	Modified int64 `json:"modified"`
}

type Value struct {
	Number string `json:"number,omitempty"`
	Hash   string `json:"hash,omitempty"`
}

type Snapshot struct {
	Version        int               `json:"version"`
	Drill          string            `json:"drill"`
	CapturedAt     time.Time         `json:"captured_at"`
	BackupLabel    string            `json:"backup_label"`
	BackupStopLSN  string            `json:"backup_stop_lsn,omitempty"`
	BackupStopTime time.Time         `json:"backup_stop_time"`
	Database       string            `json:"database"`
	ServerVersion  string            `json:"server_version"`
	ServerMajor    int               `json:"server_major"`
	Encoding       string            `json:"encoding"`
	Collate        string            `json:"collate"`
	Ctype          string            `json:"ctype"`
	Bootstrap      string            `json:"bootstrap_role"`
	Extensions     map[string]string `json:"extensions"`
	SchemaHash     string            `json:"schema_hash"`
	Objects        []Object          `json:"objects"`
	Tables         []TableCount      `json:"tables"`
	ExactCounts    map[string]int64  `json:"exact_counts"`
	Assertions     map[string]Value  `json:"assertions"`
}

func NewValue(raw string) Value {
	if numberPattern.MatchString(raw) {
		return Value{Number: raw}
	}
	sum := sha256.Sum256([]byte(raw))
	return Value{Hash: hex.EncodeToString(sum[:])}
}

var numberPattern = regexp.MustCompile(`^-?\d+(\.\d+)?$`)

func (v Value) Equal(o Value) bool { return v == o }

func (v Value) String() string {
	if v.Number != "" {
		return v.Number
	}
	return "hash " + v.Hash[:12]
}

func Hash(objects []Object) string {
	sorted := slices.Clone(objects)
	SortObjects(sorted)
	h := sha256.New()
	for _, o := range sorted {
		fmt.Fprintf(h, "%s\x00%s\x00%s\x00", o.Kind, o.Identity, normalizeDefinition(o.Definition))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func SortObjects(o []Object) {
	slices.SortFunc(o, func(a, b Object) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.Identity, b.Identity)
	})
}

func normalizeDefinition(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

func BindParameters(sql string, stop time.Time, lsn string) string {
	params := map[string]string{
		"backup_stop_time": "'" + stop.UTC().Format(time.RFC3339) + "'::timestamptz",
		"backup_stop_lsn":  "'" + lsn + "'::pg_lsn",
	}
	var out strings.Builder
	inString := false
	for i := 0; i < len(sql); {
		c := sql[i]
		if c == '\'' {
			inString = !inString
		}
		if c == ':' && !inString && (i == 0 || sql[i-1] != ':') && i+1 < len(sql) && sql[i+1] != ':' {
			matched := false
			for name, lit := range params {
				rest := sql[i+1:]
				if strings.HasPrefix(rest, name) && !isIdentChar(rest, len(name)) {
					out.WriteString(lit)
					i += 1 + len(name)
					matched = true
					break
				}
			}
			if matched {
				continue
			}
		}
		out.WriteByte(c)
		i++
	}
	return out.String()
}

func isIdentChar(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	c := s[i]
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func QuoteTable(t string) string {
	schema, table, _ := strings.Cut(t, ".")
	return `"` + schema + `"."` + table + `"`
}

func ParseInt(s string) int64 {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return -1
	}
	return v
}

func Save(dir string, s *Snapshot) (string, error) {
	target := filepath.Join(dir, s.Drill)
	if err := os.MkdirAll(target, 0o750); err != nil {
		return "", fmt.Errorf("create fingerprint directory: %w", err)
	}
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return "", fmt.Errorf("encode fingerprint: %w", err)
	}
	name := s.CapturedAt.UTC().Format("20060102T150405.000Z") + "-" + sanitize(s.BackupLabel) + ".json"
	tmp, err := os.CreateTemp(target, ".fingerprint-*")
	if err != nil {
		return "", fmt.Errorf("write fingerprint: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		return "", fmt.Errorf("write fingerprint: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("write fingerprint: %w", err)
	}
	path := filepath.Join(target, name)
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", fmt.Errorf("write fingerprint: %w", err)
	}
	return path, nil
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ' ' {
			return '_'
		}
		return r
	}, s)
}

var ErrNone = errors.New("no fingerprint has been captured for this drill")

func Load(dir, drill, label string) (snap *Snapshot, exact bool, err error) {
	entries, err := os.ReadDir(filepath.Join(dir, drill))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, ErrNone
	}
	if err != nil {
		return nil, false, fmt.Errorf("read fingerprints: %w", err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return nil, false, ErrNone
	}
	slices.Sort(names)
	pick := names[len(names)-1]
	suffix := "-" + sanitize(label) + ".json"
	for i := len(names) - 1; i >= 0; i-- {
		if strings.HasSuffix(names[i], suffix) {
			pick, exact = names[i], true
			break
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, drill, pick))
	if err != nil {
		return nil, false, fmt.Errorf("read fingerprint: %w", err)
	}
	snap = &Snapshot{}
	if err := json.Unmarshal(b, snap); err != nil {
		return nil, false, fmt.Errorf("fingerprint %s is damaged: %w", pick, err)
	}
	return snap, exact, nil
}
