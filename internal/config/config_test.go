package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goalExample = `version: 1
drill:
  name: billing-prod
  rto_target: 30m
  restore_timeout: 2h
source:
  type: pgbackrest            # or: pgdump
  stanza: billing
  repo:
    type: s3
    bucket: acme-pg-backups
    region: eu-central-1
    path: /pgbackrest
    credentials: { from_env: true }
  cipher_pass: { file: /run/secrets/pgbr_cipher }
recovery:
  target: latest              # or: { time: "2026-11-01T02:00:00Z" } or { lsn: "0/5000060" }
fingerprint:
  dsn: { env: POL_FINGERPRINT_DSN }   # read-only role
  exact_count_tables: [public.invoices, public.customers]
  row_count_tolerance: 0.5%
  heartbeat: { enabled: false, interval: 30s }
assertions:
  - name: invoices_up_to_backup
    sql: "SELECT count(*) FROM invoices WHERE created_at < :backup_stop_time"
    expect: { equals_fingerprint: true }
sandbox:
  runtime: docker
  image: postgres:{{major}}
  cpus: 2
  memory: 8GiB
  network: none
checks:
  amcheck: { enabled: true, time_budget: 20m }
evidence:
  path: /var/lib/pol/evidence.jsonl
  sign_key: /etc/pol/ed25519.key
report:
  dir: /var/lib/pol/reports
notify:
  on: [fail, warn]
  slack: { webhook: { env: POL_SLACK_WEBHOOK } }
`

func TestGoalExampleParses(t *testing.T) {
	c, err := Parse([]byte(goalExample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Drill.RTOTarget.D() != 30*time.Minute {
		t.Errorf("rto_target = %v", c.Drill.RTOTarget.D())
	}
	if c.Drill.MaxAge.D() != 26*time.Hour {
		t.Errorf("max_age default = %v", c.Drill.MaxAge.D())
	}
	if int64(c.Sandbox.Memory) != 8<<30 {
		t.Errorf("memory = %d", c.Sandbox.Memory)
	}
	if !c.Recovery.Target.Latest {
		t.Error("target should be latest")
	}
	if got := float64(c.Fingerprint.RowCountTolerance); got < 0.00499 || got > 0.00501 {
		t.Errorf("tolerance = %v", got)
	}
	if got := c.ImageFor(17); got != "postgres:17" {
		t.Errorf("ImageFor = %q", got)
	}
	if c.Fingerprint.Dir != "/var/lib/pol/fingerprints" {
		t.Errorf("fingerprint dir default = %q", c.Fingerprint.Dir)
	}
}

func TestShippedExampleParses(t *testing.T) {
	if _, err := Parse(Example); err != nil {
		t.Fatalf("example.yaml: %v", err)
	}
}

func TestValidationNamesField(t *testing.T) {
	cases := []struct {
		name, from, to, want string
	}{
		{"missing bucket", "    bucket: acme-pg-backups\n", "", "source.repo.bucket: required"},
		{"bad version", "version: 1", "version: 2", "version: must be 1"},
		{"bad source", "type: pgbackrest ", "type: walg ", "source.type: must be pgbackrest or pgdump"},
		{"missing stanza", "  stanza: billing\n", "", "source.stanza: required"},
		{"inline secret", "dsn: { env: POL_FINGERPRINT_DSN }", "dsn: postgres://u:hunter2@h/d", "fingerprint.dsn: "},
		{"inline cipher", "cipher_pass: { file: /run/secrets/pgbr_cipher }", "cipher_pass: hunter2", "source.cipher_pass: "},
		{"unknown nested key", "  rto_target: 30m", "  rto_target: 30m\n  rto_targt: 30m", "drill.rto_targt: unknown field"},
		{"bad duration", "rto_target: 30m", "rto_target: soon", "drill.rto_target: "},
		{"bad percent", "row_count_tolerance: 0.5%", "row_count_tolerance: 0.5", "fingerprint.row_count_tolerance: "},
		{"bad lsn", "target: latest ", "target: { lsn: nope } ", "recovery.target.lsn: must look like"},
		{"bad time", "target: latest ", "target: { time: yesterday } ", "recovery.target.time: must be RFC 3339"},
		{"bad target", "target: latest ", "target: earliest ", "recovery.target: "},
		{"bad network", "network: none", "network: bridge", "sandbox.network: must be none"},
		{"bad notify", "on: [fail, warn]", "on: [fail, always]", "notify.on[1]: must be pass, warn or fail"},
		{"bad table", "public.customers", "customers", "fingerprint.exact_count_tables[1]: must be schema.table"},
		{"bad expect", "expect: { equals_fingerprint: true }", "expect: {}", "assertions[0].expect: set exactly one"},
		{"missing evidence", "  path: /var/lib/pol/evidence.jsonl\n", "", "evidence.path: required"},
		{"bad stanza", "  stanza: billing\n", "  stanza: ../etc\n", "source.stanza: may contain only"},
		{"bad cpus type", "cpus: 2", "cpus: many", "sandbox.cpus: "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(goalExample, tc.from) {
				t.Fatalf("fixture does not contain %q", tc.from)
			}
			_, err := Parse([]byte(strings.Replace(goalExample, tc.from, tc.to, 1)))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("error leaked a secret: %q", err)
			}
		})
	}
}

func TestPgDumpRejectsPITR(t *testing.T) {
	y := strings.Replace(goalExample, "type: pgbackrest ", "type: pgdump ", 1)
	y = strings.Replace(y, "  stanza: billing\n", "", 1)
	y = strings.Replace(y, "  cipher_pass: { file: /run/secrets/pgbr_cipher }\n", "", 1)
	y = strings.Replace(y, "target: latest ", `target: { time: "2026-11-01T02:00:00Z" } `, 1)
	_, err := Parse([]byte(y))
	if err == nil || !strings.Contains(err.Error(), "recovery.target: point-in-time recovery needs") {
		t.Fatalf("got %v", err)
	}
}

func TestSecretResolutionAndRedaction(t *testing.T) {
	t.Setenv("POL_TEST_SECRET", "s3cret")
	s, err := SecretRef{Env: "POL_TEST_SECRET"}.Resolve()
	if err != nil || s.Reveal() != "s3cret" {
		t.Fatalf("env resolve: %v %q", err, s.Reveal())
	}
	if s.String() != "[redacted]" || s.LogValue().String() != "[redacted]" {
		t.Fatal("secret is not redacted")
	}
	p := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(p, []byte("fromfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = SecretRef{File: p}.Resolve()
	if err != nil || s.Reveal() != "fromfile" {
		t.Fatalf("file resolve: %v %q", err, s.Reveal())
	}
	if _, err := (SecretRef{Env: "POL_TEST_UNSET_VALUE"}).Resolve(); err == nil {
		t.Fatal("unset env should fail")
	}
}

func TestMultipleProblemsAreAllReported(t *testing.T) {
	_, err := Parse([]byte("version: 1\n"))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"drill.name: required", "source.type: required", "evidence.path: required", "report.dir: required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %q", want, err)
		}
	}
}
