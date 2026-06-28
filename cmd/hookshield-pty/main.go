package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

type result struct {
	Backend              string             `json:"backend"`
	StartedAt            string             `json:"started_at"`
	FinishedAt           string             `json:"finished_at"`
	RunnerPID            int                `json:"runner_pid"`
	ChildPID             int                `json:"child_pid,omitempty"`
	ObservedPIDs         []int              `json:"observed_pids,omitempty"`
	Connections          []connection       `json:"connections,omitempty"`
	FileEvents           []fileEvent        `json:"file_events,omitempty"`
	EnforcementTriggered bool               `json:"enforcement_triggered,omitempty"`
	EnforcementEvents    []enforcementEvent `json:"enforcement_events,omitempty"`
	ExitCode             int                `json:"exit_code"`
	Signal               string             `json:"signal,omitempty"`
	Error                string             `json:"error,omitempty"`
}

type runOutcome struct {
	ExitCode             int
	Signal               string
	ChildPID             int
	ObservedPIDs         []int
	Connections          []connection
	FileEvents           []fileEvent
	EnforcementTriggered bool
	EnforcementEvents    []enforcementEvent
	Err                  error
}

type connection struct {
	PID        int    `json:"pid"`
	Command    string `json:"command"`
	Protocol   string `json:"protocol"`
	RawName    string `json:"raw_name"`
	Local      string `json:"local,omitempty"`
	Remote     string `json:"remote,omitempty"`
	RemoteHost string `json:"remote_host,omitempty"`
	RemotePort string `json:"remote_port,omitempty"`
	State      string `json:"state,omitempty"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
}

type fileEvent struct {
	Action     string `json:"action"`
	Path       string `json:"path"`
	SizeBefore int64  `json:"size_before,omitempty"`
	SizeAfter  int64  `json:"size_after,omitempty"`
	ModBefore  string `json:"mod_before,omitempty"`
	ModAfter   string `json:"mod_after,omitempty"`
	ObservedAt string `json:"observed_at"`
}

type fileSnapshotEntry struct {
	Size    int64
	ModTime time.Time
}

type enforcementEvent struct {
	Action     string     `json:"action"`
	Reason     string     `json:"reason"`
	At         string     `json:"at"`
	Connection connection `json:"connection"`
}

type networkPolicy struct {
	Strict      bool
	DenyUnknown bool
	Blocked     map[string]bool
	Allowed     map[string]bool
}

func main() {
	resultFile := flag.String("result-file", "", "path to write JSON run result")
	flag.Parse()

	args := flag.Args()
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fail(*resultFile, result{Backend: "go-pty", StartedAt: now(), FinishedAt: now(), ExitCode: 2, Error: "missing command"})
	}

	startedAt := now()
	outcome := runPTY(args)
	out := result{
		Backend:              "go-pty",
		StartedAt:            startedAt,
		FinishedAt:           now(),
		RunnerPID:            os.Getpid(),
		ChildPID:             outcome.ChildPID,
		ObservedPIDs:         outcome.ObservedPIDs,
		Connections:          outcome.Connections,
		FileEvents:           outcome.FileEvents,
		EnforcementTriggered: outcome.EnforcementTriggered,
		EnforcementEvents:    outcome.EnforcementEvents,
		ExitCode:             outcome.ExitCode,
		Signal:               outcome.Signal,
	}
	if outcome.Err != nil {
		out.Error = outcome.Err.Error()
	}

	if writeErr := writeResult(*resultFile, out); writeErr != nil {
		fmt.Fprintf(os.Stderr, "hookshield-pty: failed writing result: %v\n", writeErr)
	}

	if outcome.Err != nil && outcome.ExitCode == 0 {
		os.Exit(1)
	}
	os.Exit(outcome.ExitCode)
}

func runPTY(args []string) runOutcome {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = os.Environ()
	projectRoot := projectRootFromEnv()
	cmd.Dir = projectRoot
	filesBefore := snapshotObservedFiles(projectRoot)

	size := currentSize()
	ptmx, err := pty.StartWithSize(cmd, size)
	if err != nil {
		return runOutcome{ExitCode: 1, Err: err}
	}
	childPID := cmd.Process.Pid
	monitor := startNetworkMonitor(childPID, loadNetworkPolicyFromEnv())
	defer func() {
		_ = ptmx.Close()
	}()

	restore, err := makeRaw()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hookshield-pty: continuing without raw terminal mode: %v\n", err)
	} else {
		defer restore()
	}

	resizeSignals := make(chan os.Signal, 1)
	signal.Notify(resizeSignals, syscall.SIGWINCH)
	defer signal.Stop(resizeSignals)
	go func() {
		for range resizeSignals {
			_ = pty.Setsize(ptmx, currentSize())
		}
	}()
	_ = pty.Setsize(ptmx, currentSize())

	copyDone := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(ptmx, os.Stdin)
		copyDone <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(os.Stdout, ptmx)
		copyDone <- struct{}{}
	}()

	waitErr := cmd.Wait()
	_ = ptmx.Close()
	<-copyDone
	observedPIDs, connections, enforcementEvents := monitor.stop()
	fileEvents := diffFileSnapshots(filesBefore, snapshotObservedFiles(projectRoot))
	enforced := len(enforcementEvents) > 0

	if waitErr == nil {
		return runOutcome{ExitCode: 0, ChildPID: childPID, ObservedPIDs: observedPIDs, Connections: connections, FileEvents: fileEvents, EnforcementTriggered: enforced, EnforcementEvents: enforcementEvents}
	}

	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		status, ok := exitErr.Sys().(syscall.WaitStatus)
		if !ok {
			return runOutcome{ExitCode: exitErr.ExitCode(), ChildPID: childPID, ObservedPIDs: observedPIDs, Connections: connections, FileEvents: fileEvents, EnforcementTriggered: enforced, EnforcementEvents: enforcementEvents, Err: waitErr}
		}
		if status.Signaled() {
			return runOutcome{ExitCode: 128 + int(status.Signal()), Signal: status.Signal().String(), ChildPID: childPID, ObservedPIDs: observedPIDs, Connections: connections, FileEvents: fileEvents, EnforcementTriggered: enforced, EnforcementEvents: enforcementEvents}
		}
		return runOutcome{ExitCode: status.ExitStatus(), ChildPID: childPID, ObservedPIDs: observedPIDs, Connections: connections, FileEvents: fileEvents, EnforcementTriggered: enforced, EnforcementEvents: enforcementEvents}
	}

	return runOutcome{ExitCode: 1, ChildPID: childPID, ObservedPIDs: observedPIDs, Connections: connections, FileEvents: fileEvents, EnforcementTriggered: enforced, EnforcementEvents: enforcementEvents, Err: waitErr}
}

type networkMonitor struct {
	rootPID int
	policy  networkPolicy
	done    chan struct{}
	stopped chan monitorResult
}

type monitorResult struct {
	pids              []int
	connections       []connection
	enforcementEvents []enforcementEvent
}

func startNetworkMonitor(rootPID int, policy networkPolicy) *networkMonitor {
	monitor := &networkMonitor{
		rootPID: rootPID,
		policy:  policy,
		done:    make(chan struct{}),
		stopped: make(chan monitorResult, 1),
	}
	go monitor.run()
	return monitor
}

func (m *networkMonitor) run() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	pids := map[int]bool{}
	connections := map[string]connection{}
	var enforcementEvents []enforcementEvent
	enforcementTriggered := false
	sample := func() {
		for _, pid := range processTree(m.rootPID) {
			pids[pid] = true
		}
		for _, conn := range snapshotConnections(sortedPIDs(pids)) {
			key := connectionKey(conn)
			existing, ok := connections[key]
			if ok {
				existing.LastSeen = conn.LastSeen
				connections[key] = existing
			} else {
				connections[key] = conn
			}
			if !enforcementTriggered {
				if event, shouldTerminate := m.enforcementDecision(conn); shouldTerminate {
					enforcementTriggered = true
					enforcementEvents = append(enforcementEvents, event)
					fmt.Fprintf(os.Stderr, "hookshield-pty: strict network enforcement: %s (%s)\n", event.Reason, conn.RawName)
					terminateProcessTree(m.rootPID)
				}
			}
		}
	}

	sample()
	for {
		select {
		case <-ticker.C:
			sample()
		case <-m.done:
			sample()
			m.stopped <- monitorResult{pids: sortedPIDs(pids), connections: sortedConnections(connections), enforcementEvents: enforcementEvents}
			return
		}
	}
}

func (m *networkMonitor) stop() ([]int, []connection, []enforcementEvent) {
	close(m.done)
	result := <-m.stopped
	return result.pids, result.connections, result.enforcementEvents
}

func (m *networkMonitor) enforcementDecision(conn connection) (enforcementEvent, bool) {
	if !m.policy.Strict || conn.Remote == "" || isLocalHost(conn.RemoteHost) {
		return enforcementEvent{}, false
	}
	remoteHost := strings.ToLower(conn.RemoteHost)
	rawName := strings.ToLower(conn.RawName)
	if hostAllowed(remoteHost, rawName, m.policy.Allowed) {
		return enforcementEvent{}, false
	}

	event := enforcementEvent{
		Action:     "terminate",
		At:         now(),
		Connection: conn,
	}
	if hostAllowed(remoteHost, rawName, m.policy.Blocked) {
		event.Reason = "matches blocked network policy"
		return event, true
	}
	if m.policy.DenyUnknown {
		event.Reason = "unknown external network connection in strict mode"
		return event, true
	}
	return enforcementEvent{}, false
}

func processTree(rootPID int) []int {
	seen := map[int]bool{rootPID: true}
	queue := []int{rootPID}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, child := range childPIDs(parent) {
			if seen[child] {
				continue
			}
			seen[child] = true
			queue = append(queue, child)
		}
	}
	return sortedPIDs(seen)
}

func childPIDs(parentPID int) []int {
	out, err := exec.Command("pgrep", "-P", strconv.Itoa(parentPID)).Output()
	if err != nil {
		return nil
	}
	var pids []int
	for _, field := range strings.Fields(string(out)) {
		pid, err := strconv.Atoi(field)
		if err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

func loadNetworkPolicyFromEnv() networkPolicy {
	return networkPolicy{
		Strict:      envFirst("HOOKSHIELD_STRICT_NETWORK", "HOOKER_STRICT_NETWORK") == "1",
		DenyUnknown: envFirst("HOOKSHIELD_DENY_UNKNOWN_NETWORK", "HOOKER_DENY_UNKNOWN_NETWORK") == "1",
		Blocked:     parseHostSet(envFirst("HOOKSHIELD_BLOCKED_HOSTS", "HOOKER_BLOCKED_HOSTS")),
		Allowed:     withDefaultAllowedHosts(parseHostSet(envFirst("HOOKSHIELD_ALLOWED_HOSTS", "HOOKER_ALLOWED_HOSTS"))),
	}
}

func parseHostSet(raw string) map[string]bool {
	values := map[string]bool{}
	if strings.TrimSpace(raw) == "" {
		return values
	}
	var items []string
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		for _, item := range strings.Split(raw, ",") {
			normalized := strings.ToLower(strings.TrimSpace(item))
			if normalized != "" {
				values[normalized] = true
			}
		}
		return values
	}
	for _, item := range items {
		normalized := strings.ToLower(strings.TrimSpace(item))
		if normalized != "" {
			values[normalized] = true
		}
	}
	return values
}

func withDefaultAllowedHosts(values map[string]bool) map[string]bool {
	for _, host := range []string{"localhost", "127.0.0.1", "::1", "0.0.0.0"} {
		values[host] = true
	}
	return values
}

func hostAllowed(remoteHost string, _ string, hosts map[string]bool) bool {
	for host := range hosts {
		if host == "" {
			continue
		}
		if remoteHost == host || strings.HasSuffix(remoteHost, "."+host) {
			return true
		}
	}
	return false
}

func isLocalHost(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" || host == "::1" || host == "0.0.0.0" {
		return true
	}
	if strings.HasPrefix(host, "127.") {
		return true
	}
	return false
}

func terminateProcessTree(rootPID int) {
	for _, pid := range processTree(rootPID) {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	go func() {
		time.Sleep(750 * time.Millisecond)
		for _, pid := range processTree(rootPID) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}()
}

func projectRootFromEnv() string {
	if root := strings.TrimSpace(envFirst("HOOKSHIELD_PROJECT_ROOT", "HOOKER_PROJECT_ROOT")); root != "" {
		return root
	}
	root, err := os.Getwd()
	if err != nil {
		return "."
	}
	return root
}

func envFirst(primary string, legacy string) string {
	if value := strings.TrimSpace(os.Getenv(primary)); value != "" {
		return value
	}
	return os.Getenv(legacy)
}

func snapshotFiles(root string) map[string]fileSnapshotEntry {
	files := map[string]fileSnapshotEntry{}
	root = filepath.Clean(root)
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := entry.Name()
		if entry.IsDir() {
			if path != root && shouldSkipSnapshotDir(root, path, name) {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		files[filepath.ToSlash(relative)] = fileSnapshotEntry{
			Size:    info.Size(),
			ModTime: info.ModTime(),
		}
		return nil
	})
	return files
}

func snapshotObservedFiles(projectRoot string) map[string]fileSnapshotEntry {
	files := snapshotFiles(projectRoot)
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return files
	}

	claudeRoot := filepath.Join(home, ".claude")
	for _, target := range []string{
		"projects",
		"history.jsonl",
		"settings.json",
		"settings.local.json",
		"todos",
		"session-env",
		"shell-snapshots",
	} {
		mergeSnapshotFiles(files, filepath.Join(claudeRoot, target), filepath.ToSlash(filepath.Join("~", ".claude", target)))
	}
	return files
}

func mergeSnapshotFiles(destination map[string]fileSnapshotEntry, root string, prefix string) {
	info, err := os.Stat(root)
	if err != nil {
		return
	}
	if info.Mode().IsRegular() {
		destination[prefix] = fileSnapshotEntry{
			Size:    info.Size(),
			ModTime: info.ModTime(),
		}
		return
	}
	if !info.IsDir() {
		return
	}
	for relative, entry := range snapshotFiles(root) {
		destination[filepath.ToSlash(filepath.Join(prefix, relative))] = entry
	}
}

func shouldSkipSnapshotDir(root string, currentPath string, name string) bool {
	switch name {
	case "node_modules", ".DS_Store":
		return true
	}

	relative, err := filepath.Rel(root, currentPath)
	if err != nil {
		return false
	}
	relative = filepath.ToSlash(relative)
	if relative == ".git" || relative == ".git/hooks" || relative == ".git/entire-sessions" || strings.HasPrefix(relative, ".git/entire-sessions/") {
		return false
	}
	if strings.HasPrefix(relative, ".git/") {
		return true
	}
	return false
}

func diffFileSnapshots(before map[string]fileSnapshotEntry, after map[string]fileSnapshotEntry) []fileEvent {
	observedAt := now()
	var events []fileEvent
	for path, afterEntry := range after {
		beforeEntry, existed := before[path]
		if !existed {
			events = append(events, fileEvent{
				Action:     "created",
				Path:       path,
				SizeAfter:  afterEntry.Size,
				ModAfter:   afterEntry.ModTime.UTC().Format(time.RFC3339Nano),
				ObservedAt: observedAt,
			})
			continue
		}
		if beforeEntry.Size != afterEntry.Size || !beforeEntry.ModTime.Equal(afterEntry.ModTime) {
			events = append(events, fileEvent{
				Action:     "modified",
				Path:       path,
				SizeBefore: beforeEntry.Size,
				SizeAfter:  afterEntry.Size,
				ModBefore:  beforeEntry.ModTime.UTC().Format(time.RFC3339Nano),
				ModAfter:   afterEntry.ModTime.UTC().Format(time.RFC3339Nano),
				ObservedAt: observedAt,
			})
		}
	}
	for path, beforeEntry := range before {
		if _, exists := after[path]; exists {
			continue
		}
		events = append(events, fileEvent{
			Action:     "deleted",
			Path:       path,
			SizeBefore: beforeEntry.Size,
			ModBefore:  beforeEntry.ModTime.UTC().Format(time.RFC3339Nano),
			ObservedAt: observedAt,
		})
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].Path == events[j].Path {
			return events[i].Action < events[j].Action
		}
		return events[i].Path < events[j].Path
	})
	return events
}

func snapshotConnections(pids []int) []connection {
	if len(pids) == 0 {
		return nil
	}
	var pidValues []string
	for _, pid := range pids {
		pidValues = append(pidValues, strconv.Itoa(pid))
	}
	var connections []connection
	for _, selector := range []string{"-iTCP", "-iUDP"} {
		out, err := exec.Command("lsof", "-nP", selector, "-a", "-p", strings.Join(pidValues, ",")).Output()
		if err != nil {
			continue
		}
		connections = append(connections, parseLsof(string(out), now())...)
	}
	return connections
}

func parseLsof(output string, seenAt string) []connection {
	var connections []connection
	lines := strings.Split(output, "\n")
	for index, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || index == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		rawName := strings.Join(fields[8:], " ")
		conn := connection{
			PID:       pid,
			Command:   fields[0],
			Protocol:  fields[7],
			RawName:   rawName,
			FirstSeen: seenAt,
			LastSeen:  seenAt,
		}
		conn.Local, conn.Remote, conn.State = parseEndpointPair(rawName)
		conn.RemoteHost, conn.RemotePort = splitHostPort(conn.Remote)
		connections = append(connections, conn)
	}
	return connections
}

func parseEndpointPair(raw string) (string, string, string) {
	state := ""
	if start := strings.LastIndex(raw, "("); start >= 0 && strings.HasSuffix(raw, ")") {
		state = strings.TrimSuffix(raw[start+1:], ")")
		raw = strings.TrimSpace(raw[:start])
	}
	if parts := strings.SplitN(raw, "->", 2); len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), state
	}
	return strings.TrimSpace(raw), "", state
}

func splitHostPort(endpoint string) (string, string) {
	if endpoint == "" {
		return "", ""
	}
	index := strings.LastIndex(endpoint, ":")
	if index <= 0 || index == len(endpoint)-1 {
		return endpoint, ""
	}
	return endpoint[:index], endpoint[index+1:]
}

func connectionKey(conn connection) string {
	return fmt.Sprintf("%d|%s|%s|%s|%s", conn.PID, conn.Protocol, conn.Local, conn.Remote, conn.State)
}

func sortedPIDs(pids map[int]bool) []int {
	out := make([]int, 0, len(pids))
	for pid := range pids {
		out = append(out, pid)
	}
	sort.Ints(out)
	return out
}

func sortedConnections(connections map[string]connection) []connection {
	keys := make([]string, 0, len(connections))
	for key := range connections {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]connection, 0, len(keys))
	for _, key := range keys {
		out = append(out, connections[key])
	}
	return out
}

func currentSize() *pty.Winsize {
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 || height <= 0 {
		return &pty.Winsize{Rows: 40, Cols: 120}
	}
	return &pty.Winsize{Rows: uint16(height), Cols: uint16(width)}
}

func makeRaw() (func(), error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return func() {}, nil
	}
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	return func() {
		_ = term.Restore(int(os.Stdin.Fd()), oldState)
	}, nil
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func writeResult(path string, out result) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func fail(resultFile string, out result) {
	_ = writeResult(resultFile, out)
	if out.Error != "" {
		fmt.Fprintln(os.Stderr, out.Error)
	}
	os.Exit(out.ExitCode)
}
