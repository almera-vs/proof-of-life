package sandbox

import (
	"strings"
	"testing"
)

func FuzzRedactValues(f *testing.F) {
	f.Add("before ", "secret-value", " after")
	f.Add("", `with "quotes" inside`, "")
	f.Fuzz(func(t *testing.T, before, value, after string) {
		if len(value) < 8 || strings.ContainsAny(value, "\"\\\n") || strings.Contains(before+after, value) {
			return
		}
		msg := before + `ERROR:  invalid input syntax for type integer: "` + value + `"` + after
		if strings.Contains(RedactValues(msg), value) {
			t.Fatalf("value survived: %q", RedactValues(msg))
		}
	})
}
