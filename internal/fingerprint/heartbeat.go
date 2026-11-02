package fingerprint

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const HeartbeatTable = "public.pol_heartbeat"

const heartbeatRetention = "35 days"

func RunHeartbeat(ctx context.Context, dsn string, interval time.Duration, once bool) error {
	conn, err := Connect(ctx, dsn, false)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := writeHeartbeat(ctx, conn); err != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			return err
		}
		if once {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func writeHeartbeat(ctx context.Context, conn *Conn) error {
	if _, err := conn.Query(ctx, "", "INSERT INTO "+HeartbeatTable+" (ts) VALUES (now())"); err != nil {
		return fmt.Errorf("write heartbeat: %w", err)
	}
	if _, err := conn.Query(ctx, "", "DELETE FROM "+HeartbeatTable+" WHERE ts < now() - interval '"+heartbeatRetention+"'"); err != nil {
		return fmt.Errorf("prune heartbeats: %w", err)
	}
	return nil
}
