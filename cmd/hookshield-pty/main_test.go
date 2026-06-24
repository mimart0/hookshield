package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseLsofEstablishedTCP(t *testing.T) {
	output := `COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node    12345 mike   18u  IPv4 0x1111111111111111      0t0  TCP 127.0.0.1:53321->93.184.216.34:443 (ESTABLISHED)
`
	connections := parseLsof(output, "2026-06-19T00:00:00Z")
	if len(connections) != 1 {
		t.Fatalf("expected one connection, got %d", len(connections))
	}
	conn := connections[0]
	if conn.PID != 12345 {
		t.Fatalf("PID = %d, want 12345", conn.PID)
	}
	if conn.Protocol != "TCP" {
		t.Fatalf("Protocol = %q, want TCP", conn.Protocol)
	}
	if conn.Local != "127.0.0.1:53321" {
		t.Fatalf("Local = %q", conn.Local)
	}
	if conn.Remote != "93.184.216.34:443" {
		t.Fatalf("Remote = %q", conn.Remote)
	}
	if conn.RemoteHost != "93.184.216.34" || conn.RemotePort != "443" {
		t.Fatalf("remote split = %q:%q", conn.RemoteHost, conn.RemotePort)
	}
	if conn.State != "ESTABLISHED" {
		t.Fatalf("State = %q", conn.State)
	}
}

func TestParseLsofListenSocket(t *testing.T) {
	output := `COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node    12345 mike   19u  IPv6 0x2222222222222222      0t0  TCP *:3000 (LISTEN)
`
	connections := parseLsof(output, "2026-06-19T00:00:00Z")
	if len(connections) != 1 {
		t.Fatalf("expected one connection, got %d", len(connections))
	}
	conn := connections[0]
	if conn.Local != "*:3000" {
		t.Fatalf("Local = %q", conn.Local)
	}
	if conn.Remote != "" {
		t.Fatalf("Remote = %q, want empty", conn.Remote)
	}
	if conn.State != "LISTEN" {
		t.Fatalf("State = %q", conn.State)
	}
}

func TestParseHostSetJSON(t *testing.T) {
	hosts := parseHostSet(`["example.com","93.184.216.34"]`)
	if !hosts["example.com"] {
		t.Fatal("expected example.com host")
	}
	if !hosts["93.184.216.34"] {
		t.Fatal("expected resolved IP host")
	}
}

func TestStrictEnforcementTerminatesUnknownExternalConnection(t *testing.T) {
	monitor := &networkMonitor{
		rootPID: 123,
		policy: networkPolicy{
			Strict:      true,
			DenyUnknown: true,
			Blocked:     map[string]bool{},
			Allowed:     withDefaultAllowedHosts(map[string]bool{}),
		},
	}
	event, terminate := monitor.enforcementDecision(connection{
		Remote:     "93.184.216.34:443",
		RemoteHost: "93.184.216.34",
		RawName:    "127.0.0.1:50000->93.184.216.34:443 (ESTABLISHED)",
	})
	if !terminate {
		t.Fatal("expected strict unknown external connection to terminate")
	}
	if event.Reason != "unknown external network connection in strict mode" {
		t.Fatalf("reason = %q", event.Reason)
	}
}

func TestStrictEnforcementAllowsLoopback(t *testing.T) {
	monitor := &networkMonitor{
		rootPID: 123,
		policy: networkPolicy{
			Strict:      true,
			DenyUnknown: true,
			Blocked:     map[string]bool{},
			Allowed:     withDefaultAllowedHosts(map[string]bool{}),
		},
	}
	_, terminate := monitor.enforcementDecision(connection{
		Remote:     "127.0.0.1:3000",
		RemoteHost: "127.0.0.1",
		RawName:    "127.0.0.1:50000->127.0.0.1:3000 (ESTABLISHED)",
	})
	if terminate {
		t.Fatal("expected loopback connection to be allowed")
	}
}

func TestDiffFileSnapshots(t *testing.T) {
	beforeTime := time.Date(2026, 6, 19, 1, 0, 0, 0, time.UTC)
	afterTime := beforeTime.Add(time.Second)
	events := diffFileSnapshots(map[string]fileSnapshotEntry{
		"deleted.txt":  {Size: 5, ModTime: beforeTime},
		"modified.txt": {Size: 5, ModTime: beforeTime},
		"same.txt":     {Size: 10, ModTime: beforeTime},
	}, map[string]fileSnapshotEntry{
		"created.txt":  {Size: 3, ModTime: afterTime},
		"modified.txt": {Size: 8, ModTime: afterTime},
		"same.txt":     {Size: 10, ModTime: beforeTime},
	})

	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	actions := map[string]string{}
	for _, event := range events {
		actions[event.Path] = event.Action
	}
	if actions["created.txt"] != "created" {
		t.Fatalf("created.txt action = %q", actions["created.txt"])
	}
	if actions["modified.txt"] != "modified" {
		t.Fatalf("modified.txt action = %q", actions["modified.txt"])
	}
	if actions["deleted.txt"] != "deleted" {
		t.Fatalf("deleted.txt action = %q", actions["deleted.txt"])
	}
}

func TestSnapshotFilesIncludesEntireGitSessionMetadataButSkipsObjectDatabase(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(relative string, contents string) {
		fullPath := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mustWrite(".git/hooks/pre-push", "entire hooks git pre-push")
	mustWrite(".git/entire-sessions/session.json", `{"last_prompt":"secret"}`)
	mustWrite(".git/objects/aa/bb", "object noise")
	mustWrite("src/app.js", "code")

	files := snapshotFiles(root)
	if _, ok := files[".git/hooks/pre-push"]; !ok {
		t.Fatal("expected .git/hooks/pre-push to be monitored")
	}
	if _, ok := files[".git/entire-sessions/session.json"]; !ok {
		t.Fatal("expected .git/entire-sessions/session.json to be monitored")
	}
	if _, ok := files[".git/objects/aa/bb"]; ok {
		t.Fatal("expected .git/objects to stay skipped")
	}
	if _, ok := files["src/app.js"]; !ok {
		t.Fatal("expected ordinary project files to be monitored")
	}
}
