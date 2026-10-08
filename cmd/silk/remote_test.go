package main

import "testing"

func TestTunnelURL(t *testing.T) {
	for line, want := range map[string]string{
		"2026-10-08T07:00:00Z INF |  https://isaac-tourist-expo-mil.trycloudflare.com                            |": "https://isaac-tourist-expo-mil.trycloudflare.com",
		"INF Requesting new quick Tunnel on trycloudflare.com...":                                                   "",
		"see https://www.cloudflare.com/website-terms/":                                                             "",
		"http://plain.trycloudflare.com":                                                                            "",
	} {
		if got := tunnelURL(line); got != want {
			t.Errorf("tunnelURL(%q) = %q, want %q", line, got, want)
		}
	}
}
