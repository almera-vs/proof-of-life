package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

type SecretRef struct {
	Env  string `yaml:"env"`
	File string `yaml:"file"`
}

func (s *SecretRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return errors.New("secrets cannot be written inline; reference them with env or file")
	}
	type plain SecretRef
	var p plain
	if err := n.Decode(&p); err != nil {
		return errors.New("secrets must be a mapping with env or file")
	}
	*s = SecretRef(p)
	return nil
}

func (s SecretRef) IsZero() bool { return s.Env == "" && s.File == "" }

func (s SecretRef) Resolve() (Secret, error) {
	switch {
	case s.Env != "" && s.File != "":
		return "", errors.New("set either env or file, not both")
	case s.Env != "":
		v, ok := os.LookupEnv(s.Env)
		if !ok || v == "" {
			return "", fmt.Errorf("environment variable %s is not set", s.Env)
		}
		return Secret(v), nil
	case s.File != "":
		b, err := os.ReadFile(s.File)
		if err != nil {
			return "", fmt.Errorf("read secret file: %w", err)
		}
		return Secret(strings.TrimRight(string(b), "\r\n")), nil
	}
	return "", errors.New("no env or file given")
}

type Secret string

func (Secret) String() string { return "[redacted]" }

func (Secret) GoString() string { return "[redacted]" }

func (Secret) LogValue() slog.Value { return slog.StringValue("[redacted]") }

func (Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

func (s Secret) Reveal() string { return string(s) }
