package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	SourcePgBackRest = "pgbackrest"
	SourcePgDump     = "pgdump"
)

type Config struct {
	Version     int          `yaml:"version"`
	Drill       Drill        `yaml:"drill"`
	Source      Source       `yaml:"source"`
	Recovery    Recovery     `yaml:"recovery"`
	Fingerprint *Fingerprint `yaml:"fingerprint"`
	Assertions  []Assertion  `yaml:"assertions"`
	Sandbox     Sandbox      `yaml:"sandbox"`
	Checks      Checks       `yaml:"checks"`
	Evidence    Evidence     `yaml:"evidence"`
	Report      Report       `yaml:"report"`
	Notify      Notify       `yaml:"notify"`
	Metrics     Metrics      `yaml:"metrics"`
}

type Drill struct {
	Name           string   `yaml:"name"`
	RTOTarget      Duration `yaml:"rto_target"`
	RestoreTimeout Duration `yaml:"restore_timeout"`
	MaxAge         Duration `yaml:"max_age"`
}

type Source struct {
	Type       string     `yaml:"type"`
	Stanza     string     `yaml:"stanza"`
	Repo       Repo       `yaml:"repo"`
	CipherPass *SecretRef `yaml:"cipher_pass"`

	Pattern string `yaml:"pattern"`

	ToolImage string `yaml:"tool_image"`
}

type Repo struct {
	Type      string `yaml:"type"`
	Bucket    string `yaml:"bucket"`
	Region    string `yaml:"region"`
	Path      string `yaml:"path"`
	Endpoint  string `yaml:"endpoint"`
	Port      int    `yaml:"port"`
	URIStyle  string `yaml:"uri_style"`
	VerifyTLS *bool  `yaml:"verify_tls"`

	ReadGID     int         `yaml:"read_gid"`
	Credentials Credentials `yaml:"credentials"`
}

type Credentials struct {
	FromEnv   bool       `yaml:"from_env"`
	AccessKey *SecretRef `yaml:"access_key"`
	SecretKey *SecretRef `yaml:"secret_key"`
}

type Recovery struct {
	Target RecoveryTarget `yaml:"target"`
}

type Fingerprint struct {
	DSN               SecretRef `yaml:"dsn"`
	Dir               string    `yaml:"dir"`
	ExactCountTables  []string  `yaml:"exact_count_tables"`
	RowCountTolerance Percent   `yaml:"row_count_tolerance"`
	Heartbeat         Heartbeat `yaml:"heartbeat"`
}

type Heartbeat struct {
	Enabled  bool       `yaml:"enabled"`
	Interval Duration   `yaml:"interval"`
	DSN      *SecretRef `yaml:"dsn"`
}

type Assertion struct {
	Name   string `yaml:"name"`
	SQL    string `yaml:"sql"`
	Expect Expect `yaml:"expect"`
}

type Expect struct {
	EqualsFingerprint bool    `yaml:"equals_fingerprint"`
	Equals            *string `yaml:"equals"`
}

type Sandbox struct {
	Runtime string   `yaml:"runtime"`
	Image   string   `yaml:"image"`
	CPUs    float64  `yaml:"cpus"`
	Memory  ByteSize `yaml:"memory"`
	Network string   `yaml:"network"`

	RestoreNetwork string `yaml:"restore_network"`

	Superuser string `yaml:"superuser"`
}

type Checks struct {
	Amcheck Amcheck `yaml:"amcheck"`
}

type Amcheck struct {
	Enabled    bool     `yaml:"enabled"`
	TimeBudget Duration `yaml:"time_budget"`
}

type Evidence struct {
	Path    string `yaml:"path"`
	SignKey string `yaml:"sign_key"`
}

type Report struct {
	Dir string `yaml:"dir"`
}

type Notify struct {
	On      []string `yaml:"on"`
	Slack   *Slack   `yaml:"slack"`
	Webhook *Webhook `yaml:"webhook"`
	SMTP    *SMTP    `yaml:"smtp"`
}

type Slack struct {
	Webhook SecretRef `yaml:"webhook"`
}

type Webhook struct {
	URL SecretRef `yaml:"url"`
}

type SMTP struct {
	Host     string     `yaml:"host"`
	Port     int        `yaml:"port"`
	Username string     `yaml:"username"`
	Password *SecretRef `yaml:"password"`

	AllowPlaintext bool     `yaml:"allow_plaintext"`
	From           string   `yaml:"from"`
	To             []string `yaml:"to"`
}

type Metrics struct {
	Textfile string `yaml:"textfile"`
}

type RecoveryTarget struct {
	Latest bool
	Time   string
	LSN    string
}

func (r *RecoveryTarget) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		if n.Value != "latest" {
			return fmt.Errorf("invalid target %q, expected latest, { time: ... } or { lsn: ... }", n.Value)
		}
		r.Latest = true
		return nil
	}
	var m struct {
		Time string `yaml:"time"`
		LSN  string `yaml:"lsn"`
	}
	if err := n.Decode(&m); err != nil {
		return fmt.Errorf("invalid target, expected latest, { time: ... } or { lsn: ... }")
	}
	r.Time, r.LSN = m.Time, m.LSN
	return nil
}

func Load(file string) (*Config, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	return Parse(b)
}

func Parse(b []byte) (*Config, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("parse configuration: %w", err)
	}
	if len(root.Content) == 0 {
		return nil, errors.New("parse configuration: the file is empty")
	}
	if errs := unknownFields(root.Content[0], "", typeOfConfig); len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	cfg := &Config{}
	if errs := decodeFields(root.Content[0], "", cfg); len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse configuration: %w", err)
	}
	cfg.applyDefaults()
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	setDefault(&c.Drill.MaxAge, Duration(26*time.Hour))
	setDefault(&c.Sandbox.Runtime, "docker")
	setDefault(&c.Sandbox.Image, "postgres:{{major}}")
	setDefault(&c.Sandbox.Network, "none")
	setDefault(&c.Sandbox.RestoreNetwork, "bridge")
	setDefault(&c.Sandbox.Superuser, "postgres")
	setDefault(&c.Sandbox.CPUs, 2)
	setDefault(&c.Sandbox.Memory, ByteSize(4<<30))
	setDefault(&c.Recovery.Target, RecoveryTarget{Latest: true})
	setDefault(&c.Checks.Amcheck.TimeBudget, Duration(20*time.Minute))
	if c.Source.Repo.Type == "s3" {
		setDefault(&c.Source.Repo.URIStyle, "host")
	}
	if c.Fingerprint != nil {
		setDefault(&c.Fingerprint.Dir, path.Join(path.Dir(c.Evidence.Path), "fingerprints"))
		setDefault(&c.Fingerprint.Heartbeat.Interval, Duration(30*time.Second))
	}
}

func setDefault[T comparable](field *T, def T) {
	var zero T
	if *field == zero {
		*field = def
	}
}

func (c *Config) ImageFor(major int) string {
	return strings.ReplaceAll(c.Sandbox.Image, "{{major}}", fmt.Sprint(major))
}
