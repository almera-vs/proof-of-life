//go:build !windows

package docker

import (
	"context"
	"errors"
	"net"
)

const defaultHost = "unix:///var/run/docker.sock"

func dialPipe(context.Context, string) (net.Conn, error) {
	return nil, errors.New("npipe:// is only available on Windows")
}
