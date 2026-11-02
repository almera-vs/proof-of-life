//go:build windows

package docker

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

const defaultHost = "npipe:////./pipe/docker_engine"

func dialPipe(ctx context.Context, path string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, path)
}
