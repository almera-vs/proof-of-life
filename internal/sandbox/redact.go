package sandbox

import "regexp"

var valuePatterns = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`(invalid input (?:syntax|value) for [^:]+: )"(?:[^"\\]|\\.)*"`), `$1"…"`},
	{regexp.MustCompile(`value "(?:[^"\\]|\\.)*" is out of range`), `value "…" is out of range`},
	{regexp.MustCompile(`Key \(([^)]*)\)=\((?:.*)\)`), `Key ($1)=(…)`},
	{regexp.MustCompile(`Failing row contains \(.*\)`), `Failing row contains (…)`},
	{regexp.MustCompile(`(invalid byte sequence for encoding "[^"]+": ).*`), `$1…`},
	{regexp.MustCompile(`(character with byte sequence ).*`), `$1…`},
	{regexp.MustCompile(`(date/time field value out of range: )"(?:[^"\\]|\\.)*"`), `$1"…"`},
	{regexp.MustCompile(`(time zone "[^"]*" not recognized)`), `$1`},
}

func RedactValues(msg string) string {
	for _, p := range valuePatterns {
		msg = p.re.ReplaceAllString(msg, p.with)
	}
	return msg
}
