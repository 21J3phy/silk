package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/21J3phy/silk/pkg/client"
)

type inboxStub struct {
	called string
	wait   time.Duration
	ctx    context.Context
	err    error
	result *client.SyncResult
}

func (s *inboxStub) Sync(ctx context.Context, wait time.Duration) (*client.SyncResult, error) {
	s.called, s.wait, s.ctx = "sync", wait, ctx
	return s.result, s.err
}
func (s *inboxStub) Receive(ctx context.Context, wait time.Duration) (*client.SyncResult, error) {
	s.called, s.wait, s.ctx = "receive", wait, ctx
	return s.result, s.err
}
func TestReceiveInboxPolicy(t *testing.T) {
	for _, only := range []bool{false, true} {
		for _, failure := range []bool{false, true} {
			ctx, cancel := context.WithCancel(context.Background())
			s := &inboxStub{result: &client.SyncResult{Cursor: 42}}
			if failure {
				s.err = errors.New("synthetic failure")
				s.result = nil
			}
			got, err := receiveInbox(ctx, s, 25*time.Second, only)
			cancel()
			want := "sync"
			if only {
				want = "receive"
			}
			if s.called != want || s.wait != 25*time.Second || s.ctx != ctx || got != s.result || err != s.err {
				t.Fatalf("only=%v failure=%v: call=%q wait=%v result=%v error=%v", only, failure, s.called, s.wait, got, err)
			}
		}
	}
}
