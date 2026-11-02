package sandbox

import (
	"strings"
	"testing"
)

func TestRedactValues(t *testing.T) {
	cases := map[string]string{
		`ERROR:  invalid input syntax for type integer: "alice@example.com"`:             `ERROR:  invalid input syntax for type integer: "…"`,
		`ERROR:  invalid input value for enum invoice_state: "secret-state"`:             `ERROR:  invalid input value for enum invoice_state: "…"`,
		`ERROR:  value "99999999999" is out of range for type integer`:                   `ERROR:  value "…" is out of range for type integer`,
		`ERROR:  duplicate key value violates unique constraint "x" Key (email)=(a@b.c)`: `ERROR:  duplicate key value violates unique constraint "x" Key (email)=(…)`,
		`DETAIL:  Failing row contains (1, 4111 1111 1111 1111).`:                        `DETAIL:  Failing row contains (…).`,
		`ERROR:  invalid byte sequence for encoding "UTF8": 0xc3 0x28`:                   `ERROR:  invalid byte sequence for encoding "UTF8": …`,
		`ERROR:  date/time field value out of range: "2026-13-45"`:                       `ERROR:  date/time field value out of range: "…"`,
		`ERROR:  relation "public.invoices" does not exist`:                              `ERROR:  relation "public.invoices" does not exist`,
		`ERROR:  invalid input syntax for type integer: "a \"quoted\" value"`:            `ERROR:  invalid input syntax for type integer: "…"`,
	}
	for in, want := range cases {
		if got := RedactValues(in); got != want {
			t.Errorf("\n in: %s\ngot: %s\nwant %s", in, got, want)
		}
	}
	for _, leak := range []string{"alice@example.com", "4111", "a@b.c", "secret-state"} {
		for in := range cases {
			if strings.Contains(RedactValues(in), leak) {
				t.Errorf("%q survived in %q", leak, RedactValues(in))
			}
		}
	}
}
