package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/wire"
)

// liveBench measures the hosted relay from this machine: send, receive, ack.
// It registers two agents with real postage (they stay on the public ledger).
func liveBench(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("live", flag.ExitOnError)
	base := fs.String("relay", "https://silk-relay.vercel.app", "relay URL")
	samples := fs.Int("samples", 100, "roundtrip samples")
	outPath := fs.String("out", "bench/results/live.json", "result file")
	fs.Parse(args)
	a := newAPI(*base, 2)
	var info struct {
		PoW struct {
			RegisterBits uint8 `json:"register_bits"`
		} `json:"pow"`
	}
	t0 := time.Now()
	data, _, err := a.do(ctx, "GET", "/v2/info", nil, "")
	if err != nil {
		return err
	}
	json.Unmarshal(data, &info)
	infoMs := float64(time.Since(t0).Microseconds()) / 1000
	x, err := newAgent(ctx, a, "bench-live-a", info.PoW.RegisterBits)
	if err != nil {
		return err
	}
	y, err := newAgent(ctx, a, "bench-live-b", info.PoW.RegisterBits)
	if err != nil {
		return err
	}
	p, err := handshake(ctx, a, x, y, uint32(*samples*2+50))
	if err != nil {
		return err
	}
	var sendMs, recvMs, ackMs, rtMs []float64
	for i := 0; i < *samples+5; i++ {
		start := time.Now()
		m, err := p.sealAB([]byte(text))
		if err != nil {
			return err
		}
		if _, err := a.submit(ctx, m.Raw); err != nil {
			return err
		}
		s1 := time.Now()
		path := fmt.Sprintf("/v2/inbox?after=%d&limit=100", p.cursorB)
		data, _, err := a.do(ctx, "GET", path, nil, p.b.auth("GET", path))
		if err != nil {
			return err
		}
		evs, err := relay.DecodeEvents(data)
		if err != nil {
			return err
		}
		var got *wire.Msg
		for _, ev := range evs {
			p.cursorB = ev.Seq
			if ev.Kind == wire.KindMsg {
				mm, _ := wire.DecodeMsg(ev.Frame)
				if mm != nil && mm.ID() == m.ID() {
					if _, _, err := p.sessB.Decrypt(mm); err != nil {
						return err
					}
					got = mm
				}
			}
		}
		if got == nil {
			return fmt.Errorf("message not received")
		}
		s2 := time.Now()
		if _, err := a.submit(ctx, p.ackFrame(got)); err != nil {
			return err
		}
		end := time.Now()
		if i >= 5 {
			sendMs = append(sendMs, float64(s1.Sub(start).Microseconds())/1000)
			recvMs = append(recvMs, float64(s2.Sub(s1).Microseconds())/1000)
			ackMs = append(ackMs, float64(end.Sub(s2).Microseconds())/1000)
			rtMs = append(rtMs, float64(end.Sub(start).Microseconds())/1000)
		}
	}
	// Push latency: the recipient is already long-polling when the sender sends.
	recv := newAPI(*base, 1)
	var pushMs []float64
	for i := 0; i < *samples/2+3; i++ {
		got := make(chan time.Time, 1)
		errc := make(chan error, 1)
		go func() {
			path := fmt.Sprintf("/v2/inbox?after=%d&limit=100&wait=20", p.cursorB)
			data, _, err := recv.do(ctx, "GET", path, nil, p.b.auth("GET", path))
			if err != nil {
				errc <- err
				return
			}
			evs, _ := relay.DecodeEvents(data)
			for _, ev := range evs {
				p.cursorB = ev.Seq
			}
			got <- time.Now()
		}()
		time.Sleep(300 * time.Millisecond) // let the poll reach the relay
		start := time.Now()
		m, _ := p.sealAB([]byte(text))
		if _, err := a.submit(ctx, m.Raw); err != nil {
			return err
		}
		select {
		case t := <-got:
			if i >= 3 {
				pushMs = append(pushMs, float64(t.Sub(start).Microseconds())/1000)
			}
		case err := <-errc:
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "live push (recipient waiting): p50 %.1fms p90 %.1fms\n", percentiles(pushMs).P50, percentiles(pushMs).P90)
	res := map[string]any{"push_ms": percentiles(pushMs), "relay": *base, "samples": *samples, "info_ms": infoMs, "send_ms": percentiles(sendMs), "receive_ms": percentiles(recvMs),
		"ack_ms": percentiles(ackMs), "roundtrip_ms": percentiles(rtMs), "client": machine(), "timestamp": time.Now().UTC().Format(time.RFC3339),
		"note": "From a residential connection to Vercel (iad1) + Neon Postgres (us-east-1). Includes TLS keep-alive HTTP, relay admission, and a durable Postgres commit per write."}
	fmt.Fprintf(os.Stderr, "live: send p50 %.1fms, receive p50 %.1fms, ack p50 %.1fms, roundtrip p50 %.1fms p90 %.1fms\n",
		percentiles(sendMs).P50, percentiles(recvMs).P50, percentiles(ackMs).P50, percentiles(rtMs).P50, percentiles(rtMs).P90)
	return writeResult(*outPath, res)
}
