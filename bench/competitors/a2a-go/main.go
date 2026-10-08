// Command a2a-go-server is a minimal A2A v1.0 JSON-RPC server built on the
// official Go SDK (github.com/a2aproject/a2a-go/v2). Benchmark competitor for
// Silk.
//
// It mirrors the SDK's examples/helloworld/server/jsonrpc, except that the
// executor answers every message with one agent Message "ok" (message-only
// interaction, no Task, no streaming, no LLM). The request handler uses the
// SDK defaults: in-memory task store and in-memory event queue manager.
//
//	a2a-go-server --addr 127.0.0.1:9999
package main

import (
	"context"
	"flag"
	"iter"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9999", "host:port to listen on")
	flag.Parse()

	agentCard := &a2a.AgentCard{
		Name:        "silk-bench-ok",
		Description: `Replies "ok" to every message (benchmark target).`,
		Version:     "1.0.0",
		SupportedInterfaces: []*a2a.AgentInterface{
			a2a.NewAgentInterface("http://"+*addr+"/", a2a.TransportProtocolJSONRPC),
		},
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"text/plain"},
		Capabilities:       a2a.AgentCapabilities{Streaming: false},
		Skills: []a2a.AgentSkill{{
			ID:          "ok",
			Name:        "ok",
			Description: `Acknowledge a message with "ok".`,
			Tags:        []string{"bench"},
			InputModes:  []string{"text/plain"},
			OutputModes: []string{"text/plain"},
		}},
	}

	// Message-only reply: no Task is created, so the reply carries the
	// conversation's contextId but no taskId.
	executor := a2asrv.AgentExecutorFunc(func(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			msg := a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("ok"))
			msg.ContextID = ec.ContextID
			yield(msg, nil)
		}
	})

	// SDK defaults: taskstore.NewInMemory + eventqueue.NewInMemoryManager.
	requestHandler := a2asrv.NewHandler(executor)

	mux := http.NewServeMux()
	mux.Handle("/", a2asrv.NewJSONRPCHandler(requestHandler))
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(agentCard))

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("a2a-go JSON-RPC server listening on %s", listener.Addr())
	log.Fatal(srv.Serve(listener))
}
