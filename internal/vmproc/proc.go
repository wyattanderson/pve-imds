// Package vmproc resolves the running QEMU process state for a given VMID.
//
// It reads the PID from /var/run/qemu-server/{vmid}.pid and the process
// start time from /proc/{pid}/stat. Together these form a (pid, starttime)
// tuple that uniquely identifies a process instance and detects PID reuse
// across VM restarts.
package vmproc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/afero"
)

// ProcessInfo holds the identity of a running QEMU process.
type ProcessInfo struct {
	PID       int
	StartTime uint64 // field 22 of /proc/{pid}/stat, jiffies since boot
}

// Tracker resolves QEMU process state for a given VMID.
type Tracker struct {
	fs afero.Fs
}

// New returns a Tracker that reads from fs.
// Pass afero.NewOsFs() for production and afero.NewMemMapFs() for tests.
func New(fs afero.Fs) *Tracker {
	return &Tracker{fs: fs}
}

// Lookup returns the ProcessInfo for the QEMU process running VM vmid.
// It reads the PID from /var/run/qemu-server/{vmid}.pid and the start
// time from /proc/{pid}/stat.
func (t *Tracker) Lookup(vmid int) (ProcessInfo, error) {
	pid, err := t.readPID(vmid)
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("vmid %d: read pid: %w", vmid, err)
	}
	startTime, err := t.ReadStartTime(pid)
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("vmid %d: read starttime for pid %d: %w", vmid, pid, err)
	}
	return ProcessInfo{PID: pid, StartTime: startTime}, nil
}

// ReadStartTime returns the start time (field 22 of /proc/{pid}/stat) for
// the given PID. The Stage 3 resolver calls this directly at lookup time to
// detect VM restarts without re-reading the PID file.
func (t *Tracker) ReadStartTime(pid int) (uint64, error) {
	path := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := afero.ReadFile(t.fs, path)
	if err != nil {
		return 0, err
	}
	return parseStartTime(string(data))
}

func (t *Tracker) readPID(vmid int) (int, error) {
	path := fmt.Sprintf("/var/run/qemu-server/%d.pid", vmid)
	data, err := afero.ReadFile(t.fs, path)
	if err != nil {
		return 0, err
	}
	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("parse pid %q: %w", pidStr, err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	return pid, nil
}

// parseStartTime extracts field 22 (starttime, jiffies since boot) from the
// contents of a /proc/{pid}/stat file.
//
// The format of /proc/{pid}/stat is a single space-separated line where field
// 2 is the process name enclosed in parentheses. Because the process name may
// itself contain spaces and parentheses, we locate the last ')' in the line
// and treat everything after it as fields 3 onwards.
//
//	1234 (kvm: some (vm)) S 1 ... <starttime> ...
//	                    ^--- last ')': split here
//
// Field 22 overall is at index 22-3 = 19 (0-indexed) in the post-paren fields.
func parseStartTime(stat string) (uint64, error) {
	lastParen := strings.LastIndex(stat, ")")
	if lastParen < 0 {
		return 0, errors.New("malformed stat: no closing parenthesis")
	}

	// Fields starting at field 3 (state).
	fields := strings.Fields(stat[lastParen+1:])

	const idx = 19 // (field 22) - (field 3) = 19
	if len(fields) <= idx {
		return 0, fmt.Errorf("malformed stat: only %d fields after process name, need >%d", len(fields), idx)
	}

	v, err := strconv.ParseUint(fields[idx], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse starttime %q: %w", fields[idx], err)
	}
	return v, nil
}
