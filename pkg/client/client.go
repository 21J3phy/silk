// Package client is the Silk v2 SDK: identity and key management, the
// end-to-end encrypted handshake and ratchet, a durable outbox, inbox sync,
// and independent verification of the relay's ledger.
//
// Keys and conversation state never leave the local machine. The relay only
// ever sees signed frames and ciphertext.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/21J3phy/silk/pkg/relay"
)

// Version is the client software version.
var Version = "2.0.0"

// Client is a Silk home directory plus a relay connection.
type Client struct {
	Home   string
	Config Config
	HTTP   *http.Client
	// Passphrase supplies the owner key passphrase when an owner operation needs it.
	Passphrase func() (string, error)
	offsetMs   atomic.Int64
}

// Open loads a home directory. A missing config is not an error (see Init).
func Open(home string) (*Client, error) {
	c := &Client{Home: home, HTTP: &http.Client{Timeout: 90 * time.Second}}
	c.Passphrase = func() (string, error) { return os.Getenv("SILK_PASSPHRASE"), nil }
	err := readJSON(filepath.Join(home, "config.json"), &c.Config)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if r := os.Getenv("SILK_RELAY"); r != "" {
		c.Config.Relay = r
	}
	return c, nil
}

// SaveConfig persists the configuration.
func (c *Client) SaveConfig() error {
	return writeJSON(filepath.Join(c.Home, "config.json"), c.Config, 0o600)
}

// Now is local time corrected by the measured relay clock offset.
func (c *Client) Now() time.Time {
	return time.Now().Add(time.Duration(c.offsetMs.Load()) * time.Millisecond)
}

// RelayError is an error response from the relay.
type RelayError struct {
	Status  int
	Code    string
	Message string
}

func (e *RelayError) Error() string {
	return fmt.Sprintf("relay %d %s: %s", e.Status, e.Code, e.Message)
}

// Code returns the relay error code of err, or "".
func Code(err error) string {
	var re *RelayError
	if errors.As(err, &re) {
		return re.Code
	}
	return ""
}

// retryable reports whether resending the identical frame later may succeed.
func retryable(err error) bool {
	var re *RelayError
	if !errors.As(err, &re) {
		return true // network failure: outcome unknown, resend identical frame
	}
	return re.Status >= 500 || re.Code == "slow_down"
}

type authSigner interface {
	authHeader(method, pathQuery string) string
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, auth authSigner) ([]byte, http.Header, error) {
	if c.Config.Relay == "" {
		return nil, nil, errors.New("no relay configured (run `silk init --relay URL` or set SILK_RELAY)")
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Config.Relay, "/")+path, rd)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	req.Header.Set("User-Agent", "silk/"+Version)
	if auth != nil {
		req.Header.Set("Silk-Auth", auth.authHeader(method, path))
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error.Code != "" {
			return nil, resp.Header, &RelayError{Status: resp.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
		}
		return nil, resp.Header, &RelayError{Status: resp.StatusCode, Code: "http_error", Message: strings.TrimSpace(string(data))}
	}
	return data, resp.Header, nil
}

func (c *Client) getJSON(ctx context.Context, path string, auth authSigner, v any) error {
	data, _, err := c.do(ctx, http.MethodGet, path, nil, auth)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// Info is the relay's self-description.
type Info struct {
	Protocol  string `json:"protocol"`
	Software  string `json:"software"`
	MinClient string `json:"min_client"`
	Origin    string `json:"origin"`
	LedgerKey string `json:"ledger_key"`
	TimeMs    int64  `json:"time_ms"`
	PoW       struct {
		RegisterBits  uint8 `json:"register_bits"`
		IntroBaseBits uint8 `json:"intro_base_bits"`
	} `json:"pow"`
}

// Info fetches relay metadata and calibrates the clock offset.
func (c *Client) Info(ctx context.Context) (*Info, error) {
	start := time.Now()
	var info Info
	if err := c.getJSON(ctx, "/v2/info", nil, &info); err != nil {
		return nil, err
	}
	mid := start.Add(time.Since(start) / 2)
	if off := info.TimeMs - mid.UnixMilli(); off > 1000 || off < -1000 {
		c.offsetMs.Store(off)
	}
	if info.Protocol != relay.Protocol {
		return &info, fmt.Errorf("relay speaks %q; this client speaks %q", info.Protocol, relay.Protocol)
	}
	return &info, nil
}

// Submit posts one signed frame.
func (c *Client) Submit(ctx context.Context, frame []byte) (*relay.Result, error) {
	data, _, err := c.do(ctx, http.MethodPost, "/v2/frames", frame, nil)
	if err != nil {
		return nil, err
	}
	var res relay.Result
	return &res, json.Unmarshal(data, &res)
}

// SubmitBatch posts up to relay.MaxBatch frames in one request.
func (c *Client) SubmitBatch(ctx context.Context, frames [][]byte) ([]relay.BatchItem, error) {
	data, _, err := c.do(ctx, http.MethodPost, "/v2/frames/batch", relay.EncodeBatch(frames), nil)
	if err != nil {
		return nil, err
	}
	var out []relay.BatchItem
	return out, json.Unmarshal(data, &out)
}

// Stats fetches public relay counters.
func (c *Client) Stats(ctx context.Context) (*relay.Stats, error) {
	var s relay.Stats
	return &s, c.getJSON(ctx, "/v2/stats", nil, &s)
}
