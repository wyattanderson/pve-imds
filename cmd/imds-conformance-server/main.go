// Command imds-conformance-server is a test harness for the EC2 IMDS
// conformance suite. It serves the imds.Handler over a random TCP port using
// a hard-coded fake VM identity so that the Python conformance tests can drive
// cloud-init's DataSourceEc2 against our real handler without any Proxmox
// infrastructure.
//
// On startup it prints a single "ready {json}" line to stdout (then flushes)
// so the test runner knows which port to connect to and what data to expect.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/vmconfig"
	"github.com/wyattanderson/pve-imds/internal/vmproc"
)

// fakeResolver returns a fixed VMRecord on every call, ignoring ifname and
// ifindex. This lets the conformance tests exercise the HTTP handler layer
// without a running Proxmox host.
type fakeResolver struct {
	rec *identity.VMRecord
}

func (f *fakeResolver) RecordByName(_ string, _ int32) (*identity.VMRecord, error) {
	return f.rec, nil
}

// testRecord returns the fixed VM identity the harness always serves.
// The values here are the ground truth that the Python conformance tests
// assert against.
func testRecord() *identity.VMRecord {
	mac, err := net.ParseMAC("52:54:00:12:34:56")
	if err != nil {
		panic(err)
	}
	return &identity.VMRecord{
		Node:     "pve-conformance",
		VMID:     100,
		NetIndex: 0,
		IfIndex:  3,
		Config: &vmconfig.VMConfig{
			Name:        "conformance-vm",
			OSType:      "l26",
			Description: "Test VM for EC2 IMDS conformance",
			Tags:        []string{"conformance"},
			Networks: map[int]vmconfig.NetworkDevice{
				0: {
					Model:  "virtio",
					MAC:    mac,
					Bridge: "vmbr0",
				},
			},
			Raw: map[string]string{
				"cores":  "2",
				"memory": "2048",
			},
		},
		ProcessInfo: vmproc.ProcessInfo{PID: 12345, StartTime: 999},
	}
}

// serverInfo is JSON-serialised to stdout on startup.
type serverInfo struct {
	Port     int    `json:"port"`
	VMID     int    `json:"vmid"`
	Node     string `json:"node"`
	MAC      string `json:"mac"`
	VMName   string `json:"vm_name"`
	LocalIP  string `json:"local_ipv4"`
}

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close() //nolint:errcheck

	port := ln.Addr().(*net.TCPAddr).Port
	rec := testRecord()
	resolver := &fakeResolver{rec}
	handler := imds.NewHandler(resolver, "tap100i0", rec.IfIndex)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	mac := rec.Config.Networks[0].MAC.String()
	info := serverInfo{
		Port:    port,
		VMID:    rec.VMID,
		Node:    rec.Node,
		MAC:     mac,
		VMName:  rec.Config.Name,
		LocalIP: "",
	}
	data, _ := json.Marshal(info)
	fmt.Printf("ready %s\n", data)
	// Flush stdout so the test runner's readline() does not block.
	_ = os.Stdout.Sync()

	if err := imds.Serve(ctx, ln, handler); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}
