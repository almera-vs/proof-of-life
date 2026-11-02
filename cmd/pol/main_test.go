package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/almera-vs/proof-of-life/internal/drill"
)

func TestExitCodes(t *testing.T) {
	cases := []struct {
		name   string
		res    drill.Result
		strict bool
		want   int
	}{
		{"pass", drill.Result{Verdict: drill.VerdictPass}, false, exitPass},
		{"warn", drill.Result{Verdict: drill.VerdictWarn}, false, exitPass},
		{"warn strict", drill.Result{Verdict: drill.VerdictWarn}, true, exitWarn},
		{"fail", drill.Result{Verdict: drill.VerdictFail}, false, exitFail},
		{"fail strict", drill.Result{Verdict: drill.VerdictFail}, true, exitFail},
		{"infrastructure", drill.Result{Verdict: drill.VerdictFail, InfraErr: errors.New("x")}, false, exitInfra},
		{"undelivered pass", drill.Result{Verdict: drill.VerdictPass, PostErr: errors.New("x")}, false, exitInfra},
		{"undelivered fail stays a failure", drill.Result{Verdict: drill.VerdictFail, PostErr: errors.New("x")}, false, exitFail},
		{"teardown failed", drill.Result{Verdict: drill.VerdictPass, TeardownErr: errors.New("x")}, false, exitInfra},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCode(&tc.res, tc.strict); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}

func TestUsageErrorsExitThree(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"nonsense"},
		{"validate"},
		{"run"},
		{"run", "--no-such-flag"},
		{"validate", "-c", "/does/not/exist.yaml"},
		{"evidence"},
		{"evidence", "keygen"},
		{"evidence", "verify"},
		{"fingerprint"},
		{"report"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var so, se bytes.Buffer
			if got := run(args, &so, &se); got != exitConfig {
				t.Fatalf("got %d: %s %s", got, so.String(), se.String())
			}
		})
	}
}

func TestVersionAndHelpExitZero(t *testing.T) {
	var so, se bytes.Buffer
	if got := run([]string{"version"}, &so, &se); got != exitPass || !strings.HasPrefix(so.String(), "pol ") {
		t.Fatalf("%d %q", got, so.String())
	}
	if got := run([]string{"help"}, &so, &se); got != exitPass {
		t.Fatal(got)
	}
}

func TestInitWritesAValidConfigAndKeepsExistingOnes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drill.yaml")
	var so, se bytes.Buffer
	if got := run([]string{"init", "--out", path}, &so, &se); got != exitPass {
		t.Fatalf("%d %s", got, se.String())
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"init", "--out", path}, &so, &se); got != exitConfig {
		t.Fatalf("init overwrote a file: %d", got)
	}
	if b, _ := os.ReadFile(path); string(b) != "mine" {
		t.Fatal("the file was changed")
	}
}
