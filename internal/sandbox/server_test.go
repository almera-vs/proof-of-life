package sandbox

import "testing"

func TestFatalLineSkipsConnectionNoise(t *testing.T) {
	logs := `2026-11-01 19:17:01 UTC [40] FATAL:  the database system is starting up
2026-11-01 19:17:01 UTC [9] FATAL:  recovery ended before configured recovery target was reached
2026-11-01 19:17:02 UTC [41] FATAL:  the database system is shutting down
`
	if got := FatalLine(logs); got != "recovery ended before configured recovery target was reached" {
		t.Fatalf("got %q", got)
	}
	if got := FatalLine("LOG: fine\n"); got != "" {
		t.Fatalf("got %q", got)
	}
}
