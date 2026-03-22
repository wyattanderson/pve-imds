package identity

import (
	"slices"

	"github.com/wyattanderson/pve-imds/internal/vmconfig"
)

// entry is a single cached VM identity record.
type entry struct {
	vmid     int
	netIndex int
	ifindex  int32
	config   *vmconfig.VMConfig
}

// addIfname records ifname under vmid in the secondary index, avoiding
// duplicates. Must be called with r.mu held for writing.
func (r *Resolver) addIfname(vmid int, ifname string) {
	if !slices.Contains(r.vmidToIfnames[vmid], ifname) {
		r.vmidToIfnames[vmid] = append(r.vmidToIfnames[vmid], ifname)
	}
}

// removeIfname removes ifname from the secondary index for vmid and cleans up
// the map key when the slice becomes empty. Must be called with r.mu held for
// writing.
func (r *Resolver) removeIfname(vmid int, ifname string) {
	names := r.vmidToIfnames[vmid]
	for i, n := range names {
		if n == ifname {
			last := len(names) - 1
			names[i] = names[last]
			r.vmidToIfnames[vmid] = names[:last]
			break
		}
	}
	if len(r.vmidToIfnames[vmid]) == 0 {
		delete(r.vmidToIfnames, vmid)
	}
}
