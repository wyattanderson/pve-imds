package identity

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/tapwatch"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// vmFixture holds the parameters for a single fake VM used across tests.
type vmFixture struct {
	vmid     int
	netIndex int
	ifname   string
	ifindex  int32
	mac      string // colon-separated, e.g. "BC:24:11:AA:BB:CC"
}

// confContent builds a minimal /etc/pve/qemu-server/{vmid}.conf with a single
// net device.
func confContent(vmid, netIndex int, mac string) string {
	return fmt.Sprintf(
		"name: vm%d\nostype: l26\nnet%d: virtio=%s,bridge=vmbr0,firewall=1\n",
		vmid, netIndex, mac,
	)
}

type testEnv struct {
	configFS afero.Fs
	resolver *Resolver
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	cfgFS := afero.NewMemMapFs()
	r, err := New(cfgFS, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, err)
	return &testEnv{configFS: cfgFS, resolver: r}
}

// addVM writes the config file and returns the net.HardwareAddr for the
// fixture's MAC.
func (e *testEnv) addVM(t *testing.T, f vmFixture) net.HardwareAddr {
	t.Helper()

	confPath := fmt.Sprintf("/etc/pve/qemu-server/%d.conf", f.vmid)
	require.NoError(t, afero.WriteFile(e.configFS, confPath,
		[]byte(confContent(f.vmid, f.netIndex, f.mac)), 0644))

	mac, err := net.ParseMAC(f.mac)
	require.NoError(t, err)
	return mac
}

// populate sends a Created event to the resolver for the given fixture.
func (e *testEnv) populate(t *testing.T, f vmFixture) {
	t.Helper()
	e.resolver.HandleLinkEvent(context.Background(), tapwatch.Event{
		Type:  tapwatch.Created,
		Name:  f.ifname,
		Index: f.ifindex,
	})
	// Verify the entry was actually added.
	e.resolver.mu.RLock()
	_, ok := e.resolver.entries[f.ifname]
	e.resolver.mu.RUnlock()
	require.True(t, ok, "populate: entry for %s not found in cache", f.ifname)
}

var vm100 = vmFixture{
	vmid:     100,
	netIndex: 0,
	ifname:   "tap100i0",
	ifindex:  5,
	mac:      "BC:24:11:AA:BB:CC",
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestLookupSuccess(t *testing.T) {
	env := newTestEnv(t)
	mac := env.addVM(t, vm100)
	env.populate(t, vm100)

	rec, err := env.resolver.Lookup(vm100.ifname, vm100.ifindex, mac)
	require.NoError(t, err)
	assert.Equal(t, vm100.vmid, rec.VMID)
	assert.Equal(t, vm100.netIndex, rec.NetIndex)
	assert.Equal(t, vm100.ifindex, rec.IfIndex)
	assert.Equal(t, "vm100", rec.Config.Name)
	// Node should be the real hostname.
	hostname, _ := os.Hostname()
	assert.Equal(t, hostname, rec.Node)
}

func TestLookupNotFound(t *testing.T) {
	env := newTestEnv(t)
	_, err := env.resolver.Lookup("tap999i0", 1, nil)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestLookupIfindexMismatch(t *testing.T) {
	env := newTestEnv(t)
	mac := env.addVM(t, vm100)
	env.populate(t, vm100)

	_, err := env.resolver.Lookup(vm100.ifname, vm100.ifindex+1, mac)
	assert.ErrorIs(t, err, ErrIfindexMismatch)
}

func TestLookupMACMismatch(t *testing.T) {
	env := newTestEnv(t)
	env.addVM(t, vm100)
	env.populate(t, vm100)

	wrongMAC, _ := net.ParseMAC("DE:AD:BE:EF:00:01")
	_, err := env.resolver.Lookup(vm100.ifname, vm100.ifindex, wrongMAC)
	assert.ErrorIs(t, err, ErrMACMismatch)
}

func TestHandleLinkEventCreated(t *testing.T) {
	env := newTestEnv(t)
	env.addVM(t, vm100)

	env.resolver.HandleLinkEvent(context.Background(), tapwatch.Event{
		Type:  tapwatch.Created,
		Name:  vm100.ifname,
		Index: vm100.ifindex,
	})

	env.resolver.mu.RLock()
	e, ok := env.resolver.entries[vm100.ifname]
	env.resolver.mu.RUnlock()

	require.True(t, ok)
	assert.Equal(t, vm100.vmid, e.vmid)
	assert.Equal(t, vm100.netIndex, e.netIndex)
	assert.Equal(t, vm100.ifindex, e.ifindex)
}

func TestHandleLinkEventDeleted(t *testing.T) {
	env := newTestEnv(t)
	env.addVM(t, vm100)
	env.populate(t, vm100)

	env.resolver.HandleLinkEvent(context.Background(), tapwatch.Event{
		Type:  tapwatch.Deleted,
		Name:  vm100.ifname,
		Index: vm100.ifindex,
	})

	env.resolver.mu.RLock()
	_, ok := env.resolver.entries[vm100.ifname]
	env.resolver.mu.RUnlock()
	assert.False(t, ok)
}

func TestHandleLinkEventCreatedMissingConfig(t *testing.T) {
	env := newTestEnv(t)
	// Deliberately do not write any files — populate should fail gracefully.
	env.resolver.HandleLinkEvent(context.Background(), tapwatch.Event{
		Type:  tapwatch.Created,
		Name:  vm100.ifname,
		Index: vm100.ifindex,
	})

	env.resolver.mu.RLock()
	_, ok := env.resolver.entries[vm100.ifname]
	env.resolver.mu.RUnlock()
	assert.False(t, ok, "entry must not be added when populate fails")
}

// TestVmidToIfnamesSecondaryIndex verifies that the secondary index tracks
// multiple tap interfaces belonging to the same VMID.
func TestVmidToIfnamesSecondaryIndex(t *testing.T) {
	env := newTestEnv(t)

	f0 := vmFixture{vmid: 200, netIndex: 0, ifname: "tap200i0", ifindex: 10,
		mac: "AA:BB:CC:DD:EE:01"}
	f1 := vmFixture{vmid: 200, netIndex: 1, ifname: "tap200i1", ifindex: 11,
		mac: "AA:BB:CC:DD:EE:02"}

	// Both tap interfaces share the same VMID.
	env.addVM(t, f0)
	// f1 uses the same config; write a two-NIC config instead.
	confPath := "/etc/pve/qemu-server/200.conf"
	twoNICConf := "name: vm200\nostype: l26\n" +
		"net0: virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0\n" +
		"net1: virtio=AA:BB:CC:DD:EE:02,bridge=vmbr0\n"
	require.NoError(t, afero.WriteFile(env.configFS, confPath, []byte(twoNICConf), 0644))

	env.populate(t, f0)
	env.populate(t, f1)

	env.resolver.mu.RLock()
	names := env.resolver.vmidToIfnames[200]
	env.resolver.mu.RUnlock()
	assert.ElementsMatch(t, []string{"tap200i0", "tap200i1"}, names)

	// Deleting one interface must leave the other in the index.
	env.resolver.HandleLinkEvent(context.Background(), tapwatch.Event{
		Type: tapwatch.Deleted, Name: "tap200i0", Index: 10,
	})

	env.resolver.mu.RLock()
	names = env.resolver.vmidToIfnames[200]
	env.resolver.mu.RUnlock()
	assert.Equal(t, []string{"tap200i1"}, names)
}

// TestReloadConfig verifies that ReloadConfig updates all cache entries for a
// VMID without evicting them.
func TestReloadConfig(t *testing.T) {
	env := newTestEnv(t)
	env.addVM(t, vm100)
	env.populate(t, vm100)

	// Rewrite the config with a different VM name.
	confPath := fmt.Sprintf("/etc/pve/qemu-server/%d.conf", vm100.vmid)
	updated := fmt.Sprintf("name: updated\nostype: l26\nnet0: virtio=%s,bridge=vmbr0\n", vm100.mac)
	require.NoError(t, afero.WriteFile(env.configFS, confPath, []byte(updated), 0644))

	env.resolver.ReloadConfig(vm100.vmid)

	env.resolver.mu.RLock()
	e := env.resolver.entries[vm100.ifname]
	env.resolver.mu.RUnlock()
	require.NotNil(t, e)
	assert.Equal(t, "updated", e.config.Name)
}

// TestConcurrentLookupAndPopulate verifies there are no data races when
// lookups and populates happen concurrently. Run with -race.
func TestConcurrentLookupAndPopulate(t *testing.T) {
	env := newTestEnv(t)
	mac := env.addVM(t, vm100)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Half the goroutines populate, half look up. The lookups may race with
	// population and get ErrNotFound — that is expected and not an error here.
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				env.resolver.HandleLinkEvent(context.Background(), tapwatch.Event{
					Type:  tapwatch.Created,
					Name:  vm100.ifname,
					Index: vm100.ifindex,
				})
			} else {
				//nolint:errcheck
				env.resolver.Lookup(vm100.ifname, vm100.ifindex, mac)
			}
		}(i)
	}
	wg.Wait()
}
