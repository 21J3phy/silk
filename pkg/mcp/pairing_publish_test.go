package mcp

import (
	"encoding/json"
	"errors"
	"net/url"
	"testing"
)

func TestPairingPublicationRotation(t *testing.T) {
	h, _ := newTestHTTP(t)
	old := h.PairingCode()
	var published string
	h.PairingCodeChanged = func(code string) error { published = code; return nil }
	h.mu.Lock()
	err := h.rotatePairingLocked()
	h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if published == "" || published == old || h.PairingCode() != published {
		t.Fatal("new code not published")
	}
}

func TestPairingPublicationFailureDisablesCode(t *testing.T) {
	h, _ := newTestHTTP(t)
	h.PairingCodeChanged = func(string) error { return errors.New("synthetic write failure") }
	h.mu.Lock()
	err := h.rotatePairingLocked()
	h.mu.Unlock()
	if err == nil || h.PairingCode() != "" {
		t.Fatal("publication failure did not disable pairing")
	}
}

func TestPairingPublicationErrorDoesNotIssueAuthorizationCode(t *testing.T) {
	h, ts := newTestHTTP(t)
	cb := "http://127.0.0.1:33418/callback"
	_, body := post(t, ts.URL+"/register", "", `{"redirect_uris":["`+cb+`"],"client_name":"synthetic"}`)
	var reg struct {
		ClientID string `json:"client_id"`
	}
	json.Unmarshal([]byte(body), &reg)
	_, challenge := pkce()
	v := url.Values{"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {cb}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "decision": {"approve"}, "pairing_code": {h.PairingCode()}}
	h.PairingCodeChanged = func(string) error { return errors.New("synthetic private sink failure") }
	resp, _ := form(t, ts.URL+"/authorize", v)
	if resp.StatusCode != 503 || resp.Header.Get("Location") != "" {
		t.Fatalf("issued response: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	v.Set("pairing_code", "")
	resp, _ = form(t, ts.URL+"/authorize", v)
	if resp.StatusCode != 401 {
		t.Fatalf("empty disabled pairing accepted: %d", resp.StatusCode)
	}
}
