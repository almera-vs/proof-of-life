package obs

import (
	"testing"
	"time"
)

func TestFormatDuration(t *testing.T) {
	cases := map[time.Duration]string{
		5700 * time.Millisecond:        "5.7s",
		68 * time.Second:               "1m 08s",
		13*time.Minute + 5*time.Second: "13m 05s",
		112 * time.Minute:              "1h 52m",
	}
	for in, want := range cases {
		if got := FormatDuration(in); got != want {
			t.Errorf("%v: got %q want %q", in, got, want)
		}
	}
}

func TestFormatShort(t *testing.T) {
	cases := map[time.Duration]string{30 * time.Minute: "30m", 26 * time.Hour: "26h", 90 * time.Second: "90s"}
	for in, want := range cases {
		if got := FormatShort(in); got != want {
			t.Errorf("%v: got %q want %q", in, got, want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[int64]string{512: "512 B", 2048: "2.0 KB", 412 << 30: "412 GB"}
	for in, want := range cases {
		if got := FormatBytes(in); got != want {
			t.Errorf("%d: got %q want %q", in, got, want)
		}
	}
}
