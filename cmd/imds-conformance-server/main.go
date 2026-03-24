// Command imds-conformance-server is a test harness for the IMDS conformance
// suites. It serves either an EC2-compatible or OpenStack-compatible IMDS over
// a random TCP port using a hard-coded fake VM identity so that the Python
// conformance tests can drive cloud-init's DataSource* implementations against
// our real handlers without any Proxmox infrastructure.
//
// On startup it prints a single "ready {json}" line to stdout (then flushes)
// so the test runner knows which port to connect to and what data to expect.
//
// Flags:
//
//	-emulate ec2|openstack   (default: ec2)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/imds/ec2"
	"github.com/wyattanderson/pve-imds/internal/imds/openstack"
	"github.com/wyattanderson/pve-imds/internal/vmconfig"
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
			Description: "Test VM for IMDS conformance",
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
	}
}

// serverInfo is JSON-serialised to stdout on startup.
type serverInfo struct {
	Port    int    `json:"port"`
	VMID    int    `json:"vmid"`
	Node    string `json:"node"`
	MAC     string `json:"mac"`
	VMName  string `json:"vm_name"`
	LocalIP string `json:"local_ipv4"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	emulate := flag.String("emulate", "ec2", "IMDS emulation target: ec2 or openstack")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close() //nolint:errcheck

	port := ln.Addr().(*net.TCPAddr).Port
	rec := testRecord()
	resolver := &fakeResolver{rec}

	var srv imds.Server
	switch *emulate {
	case "ec2":
		srv = ec2.NewServer()
	case "openstack":
		srv = openstack.NewServer()
	default:
		return fmt.Errorf("unknown -emulate value %q: must be ec2 or openstack", *emulate)
	}

	handler := srv.NewHandler(resolver, "tap100i0", rec.IfIndex)

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
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
