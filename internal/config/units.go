package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q, expected a value such as 30m or 2h", n.Value)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

type ByteSize int64

var byteUnits = []struct {
	suffix string
	factor int64
}{
	{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
	{"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"KB", 1e3}, {"B", 1},
}

func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseByteSize(n.Value)
	if err != nil {
		return err
	}
	*b = ByteSize(v)
	return nil
}

func ParseByteSize(s string) (int64, error) {
	for _, u := range byteUnits {
		num, ok := strings.CutSuffix(s, u.suffix)
		if !ok {
			continue
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
		if err != nil || f <= 0 {
			break
		}
		return int64(f * float64(u.factor)), nil
	}
	return 0, fmt.Errorf("invalid size %q, expected a value such as 8GiB", s)
}

type Percent float64

func (p *Percent) UnmarshalYAML(n *yaml.Node) error {
	num, ok := strings.CutSuffix(strings.TrimSpace(n.Value), "%")
	if !ok {
		return fmt.Errorf("invalid percentage %q, expected a value such as 0.5%%", n.Value)
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil || f < 0 {
		return fmt.Errorf("invalid percentage %q, expected a value such as 0.5%%", n.Value)
	}
	*p = Percent(f / 100)
	return nil
}

func (p Percent) String() string {
	return strconv.FormatFloat(float64(p)*100, 'f', -1, 64) + "%"
}
