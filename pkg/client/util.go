package client

import (
	"encoding/json"

	"golang.org/x/mod/sumdb/tlog"
)

func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

func toHashes(in [][]byte) []tlog.Hash {
	out := make([]tlog.Hash, 0, len(in))
	for _, b := range in {
		var h tlog.Hash
		copy(h[:], b)
		out = append(out, h)
	}
	return out
}

func toTreeProof(in [][]byte) tlog.TreeProof     { return tlog.TreeProof(toHashes(in)) }
func toRecordProof(in [][]byte) tlog.RecordProof { return tlog.RecordProof(toHashes(in)) }
