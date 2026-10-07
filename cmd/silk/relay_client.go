//go:build client

package main

import (
	"context"
	"errors"
)

// The client-only build (go build -tags client) leaves out the relay and its
// storage engines, which keeps every agent's `silk mcp` process smaller.
func runRelay(ctx context.Context, args []string) error {
	return errors.New("this silk build has no relay; download the full build or `go build ./cmd/silk`")
}
