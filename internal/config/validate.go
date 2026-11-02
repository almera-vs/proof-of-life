package config

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

var typeOfConfig = reflect.TypeFor[Config]()

var (
	lsnPattern   = regexp.MustCompile(`^[0-9A-Fa-f]{1,8}/[0-9A-Fa-f]{1,8}$`)
	tablePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]*\.[A-Za-z_][A-Za-z0-9_$]*$`)
	drillPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

type problems struct{ errs []error }

func (p *problems) add(field, format string, args ...any) {
	p.errs = append(p.errs, fmt.Errorf("%s: %s", field, fmt.Sprintf(format, args...)))
}

func (p *problems) required(field, value string) {
	if value == "" {
		p.add(field, "required")
	}
}

func (c *Config) validate() []error {
	p := &problems{}
	if c.Version != 1 {
		p.add("version", "must be 1")
	}
	c.validateDrill(p)
	c.validateSource(p)
	c.validateRecovery(p)
	c.validateFingerprint(p)
	c.validateAssertions(p)
	c.validateSandbox(p)
	p.required("evidence.path", c.Evidence.Path)
	p.required("evidence.sign_key", c.Evidence.SignKey)
	p.required("report.dir", c.Report.Dir)
	c.validateNotify(p)
	return p.errs
}

func (c *Config) validateDrill(p *problems) {
	switch {
	case c.Drill.Name == "":
		p.add("drill.name", "required")
	case !drillPattern.MatchString(c.Drill.Name):
		p.add("drill.name", "may contain only letters, digits, dot, dash and underscore")
	}
	if c.Drill.RTOTarget <= 0 {
		p.add("drill.rto_target", "required")
	}
	if c.Drill.RestoreTimeout <= 0 {
		p.add("drill.restore_timeout", "required")
	}
}

func (c *Config) validateSource(p *problems) {
	s := c.Source
	switch s.Type {
	case SourcePgBackRest:
		switch {
		case s.Stanza == "":
			p.add("source.stanza", "required")
		case !drillPattern.MatchString(s.Stanza):
			p.add("source.stanza", "may contain only letters, digits, dot, dash and underscore")
		}
	case SourcePgDump:
		if s.Stanza != "" {
			p.add("source.stanza", "applies only to source.type pgbackrest")
		}
		if s.CipherPass != nil {
			p.add("source.cipher_pass", "applies only to source.type pgbackrest")
		}
	case "":
		p.add("source.type", "required")
	default:
		p.add("source.type", "must be pgbackrest or pgdump, got %q", s.Type)
	}
	switch s.Repo.Type {
	case "s3":
		p.required("source.repo.bucket", s.Repo.Bucket)
		p.required("source.repo.region", s.Repo.Region)
		if !s.Repo.Credentials.FromEnv && (s.Repo.Credentials.AccessKey == nil || s.Repo.Credentials.SecretKey == nil) {
			p.add("source.repo.credentials", "set from_env: true, or both access_key and secret_key")
		}
		if s.Repo.URIStyle != "host" && s.Repo.URIStyle != "path" {
			p.add("source.repo.uri_style", "must be host or path")
		}
	case "posix":
		p.required("source.repo.path", s.Repo.Path)
	case "":
		p.add("source.repo.type", "required")
	default:
		p.add("source.repo.type", "must be s3 or posix, got %q", s.Repo.Type)
	}
	if s.CipherPass != nil {
		validateRef(p, "source.cipher_pass", *s.CipherPass)
	}
}

func (c *Config) validateRecovery(p *problems) {
	t := c.Recovery.Target
	if t.Time != "" && t.LSN != "" {
		p.add("recovery.target", "set either time or lsn, not both")
	}
	if t.Time != "" {
		if _, err := time.Parse(time.RFC3339, t.Time); err != nil {
			p.add("recovery.target.time", "must be RFC 3339, for example 2026-11-01T02:00:00Z")
		}
	}
	if t.LSN != "" && !lsnPattern.MatchString(t.LSN) {
		p.add("recovery.target.lsn", "must look like 0/5000060")
	}
	if !t.Latest && t.Time == "" && t.LSN == "" {
		p.add("recovery.target", "expected latest, { time: ... } or { lsn: ... }")
	}
	if c.Source.Type == SourcePgDump && !t.Latest {
		p.add("recovery.target", "point-in-time recovery needs source.type pgbackrest; a pg_dump archive holds one point in time")
	}
}

func (c *Config) validateFingerprint(p *problems) {
	f := c.Fingerprint
	if f == nil {
		return
	}
	validateRef(p, "fingerprint.dsn", f.DSN)
	for i, t := range f.ExactCountTables {
		if !tablePattern.MatchString(t) {
			p.add(fmt.Sprintf("fingerprint.exact_count_tables[%d]", i), "must be schema.table with plain identifiers, got %q", t)
		}
	}
	if f.Heartbeat.Enabled && f.Heartbeat.Interval <= 0 {
		p.add("fingerprint.heartbeat.interval", "must be positive")
	}
	if f.Heartbeat.DSN != nil {
		validateRef(p, "fingerprint.heartbeat.dsn", *f.Heartbeat.DSN)
	}
}

func (c *Config) validateAssertions(p *problems) {
	seen := map[string]bool{}
	for i, a := range c.Assertions {
		field := fmt.Sprintf("assertions[%d]", i)
		p.required(field+".name", a.Name)
		if seen[a.Name] {
			p.add(field+".name", "duplicate name %q", a.Name)
		}
		seen[a.Name] = true
		p.required(field+".sql", a.SQL)
		if a.Expect.EqualsFingerprint == (a.Expect.Equals != nil) {
			p.add(field+".expect", "set exactly one of equals_fingerprint or equals")
		}
		if a.Expect.EqualsFingerprint && c.Fingerprint == nil {
			p.add(field+".expect.equals_fingerprint", "needs a fingerprint section")
		}
	}
}

func (c *Config) validateSandbox(p *problems) {
	s := c.Sandbox
	if s.Runtime != "docker" {
		p.add("sandbox.runtime", "must be docker, got %q", s.Runtime)
	}
	if s.Network != "none" {
		p.add("sandbox.network", "must be none; the server never needs a network")
	}
	if s.CPUs <= 0 {
		p.add("sandbox.cpus", "must be positive")
	}
	if !strings.Contains(s.Image, ":") {
		p.add("sandbox.image", "must carry a tag or {{major}}")
	}
	if c.Checks.Amcheck.Enabled && c.Checks.Amcheck.TimeBudget <= 0 {
		p.add("checks.amcheck.time_budget", "must be positive")
	}
}

func (c *Config) validateNotify(p *problems) {
	n := c.Notify
	for i, on := range n.On {
		if !slices.Contains([]string{"pass", "warn", "fail"}, on) {
			p.add(fmt.Sprintf("notify.on[%d]", i), "must be pass, warn or fail, got %q", on)
		}
	}
	hasTarget := n.Slack != nil || n.Webhook != nil || n.SMTP != nil
	if len(n.On) > 0 && !hasTarget {
		p.add("notify", "on is set but no slack, webhook or smtp target is configured")
	}
	if n.Slack != nil {
		validateRef(p, "notify.slack.webhook", n.Slack.Webhook)
	}
	if n.Webhook != nil {
		validateRef(p, "notify.webhook.url", n.Webhook.URL)
	}
	if n.SMTP != nil {
		p.required("notify.smtp.host", n.SMTP.Host)
		p.required("notify.smtp.from", n.SMTP.From)
		if len(n.SMTP.To) == 0 {
			p.add("notify.smtp.to", "required")
		}
		if n.SMTP.Port == 0 {
			p.add("notify.smtp.port", "required")
		}
		if n.SMTP.Password != nil {
			validateRef(p, "notify.smtp.password", *n.SMTP.Password)
		}
	}
}

func validateRef(p *problems, field string, r SecretRef) {
	switch {
	case r.IsZero():
		p.add(field, "required; use env: or file:")
	case r.Env != "" && r.File != "":
		p.add(field, "set either env or file, not both")
	}
}

func unknownFields(n *yaml.Node, path string, t reflect.Type) []error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	var errs []error
	switch {
	case t.Kind() == reflect.Slice && n.Kind == yaml.SequenceNode:
		for i, item := range n.Content {
			errs = append(errs, unknownFields(item, fmt.Sprintf("%s[%d]", path, i), t.Elem())...)
		}
	case t.Kind() == reflect.Struct && n.Kind == yaml.MappingNode && !hasCustomDecoder(t):
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i].Value
			field := strings.TrimPrefix(path+"."+key, ".")
			sub, ok := fieldByTag(t, key)
			if !ok {
				errs = append(errs, fmt.Errorf("%s: unknown field", field))
				continue
			}
			errs = append(errs, unknownFields(n.Content[i+1], field, sub)...)
		}
	}
	return errs
}

func hasCustomDecoder(t reflect.Type) bool {
	return reflect.PointerTo(t).Implements(reflect.TypeFor[yaml.Unmarshaler]())
}

func fieldByTag(t reflect.Type, key string) (reflect.Type, bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		if strings.Split(f.Tag.Get("yaml"), ",")[0] == key {
			return f.Type, true
		}
	}
	return nil, false
}

func decodeFields(n *yaml.Node, path string, into any) []error {
	return decodeValue(n, path, reflect.ValueOf(into).Elem())
}

func decodeValue(n *yaml.Node, path string, v reflect.Value) []error {
	if v.Kind() == reflect.Pointer {
		v.Set(reflect.New(v.Type().Elem()))
		return decodeValue(n, path, v.Elem())
	}
	switch {
	case v.Kind() == reflect.Struct && n.Kind == yaml.MappingNode && !hasCustomDecoder(v.Type()):
		var errs []error
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i].Value
			if f, ok := structField(v, key); ok {
				errs = append(errs, decodeValue(n.Content[i+1], strings.TrimPrefix(path+"."+key, "."), f)...)
			}
		}
		return errs
	case v.Kind() == reflect.Slice && n.Kind == yaml.SequenceNode:
		var errs []error
		v.Set(reflect.MakeSlice(v.Type(), len(n.Content), len(n.Content)))
		for i, item := range n.Content {
			errs = append(errs, decodeValue(item, fmt.Sprintf("%s[%d]", path, i), v.Index(i))...)
		}
		return errs
	}
	if err := n.Decode(v.Addr().Interface()); err != nil {
		if hasCustomDecoder(v.Type()) {
			return []error{fmt.Errorf("%s: %s", path, err.Error())}
		}
		return []error{fmt.Errorf("%s: invalid value on line %d, expected %s", path, n.Line, v.Kind())}
	}
	return nil
}

func structField(v reflect.Value, key string) (reflect.Value, bool) {
	t := v.Type()
	for i := range t.NumField() {
		if strings.Split(t.Field(i).Tag.Get("yaml"), ",")[0] == key {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}
