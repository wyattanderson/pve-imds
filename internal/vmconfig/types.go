// Package vmconfig parses the main section of a Proxmox QEMU VM configuration
// file (/etc/pve/qemu-server/<VMID>.conf) into a typed Go struct.
//
// Only the main (untitled) section is parsed. All named sections — [PENDING],
// [special:cloudinit], [special:fleecing], and snapshot sections — are ignored.
// The SHA-256 digest covers the entire raw file so that any change to any section
// produces a different digest.
package vmconfig

import "net"

// VMConfig is the parsed main section of a Proxmox QEMU configuration file.
type VMConfig struct {
	// Digest is the SHA-256 of the entire raw config file (all sections).
	Digest [32]byte

	// Name is the VM name (the "name" key).
	Name string

	// OSType is the guest OS type, e.g. "l26", "win10" (the "ostype" key).
	OSType string

	// Description is accumulated from leading '#' comment lines in the main
	// section. Each line contributes one line to the description (the '#'
	// prefix and one optional space are stripped). If a "description:" key is
	// also present it overrides the comment-accumulated value.
	Description string

	// Tags is the list of VM tags. In the config file they are stored as a
	// semicolon-separated string ("foo;bar;baz"). Whitespace around each tag
	// is trimmed. A missing or empty tags line produces a nil slice.
	Tags []string

	// Networks holds the parsed network devices, indexed by net index (the N
	// in "netN"). A VM with net0 and net1 will have entries at keys 0 and 1.
	Networks map[int]NetworkDevice

	// SMBIOS holds the parsed and decoded fields from the "smbios1" key.
	// Keys present: "uuid", "product", and any other smbios1 sub-fields.
	// Fields other than "uuid" are base64-decoded when "base64=1" is set in
	// the config value. Nil if no "smbios1" key is present.
	SMBIOS map[string]string

	// Raw holds key→value pairs from the main section for keys that are not
	// explicitly typed above (e.g. "cores", "memory", "scsi0").
	// Keys present in the typed fields above are NOT duplicated here.
	Raw map[string]string
}

// NetworkDevice is a parsed "netN" entry, e.g.:
//
//	net0: virtio=BC:24:11:2C:69:EC,bridge=vnet0,firewall=1
type NetworkDevice struct {
	// Model is the NIC model string: "virtio", "e1000", "vmxnet3", etc.
	Model string

	// MAC is the hardware address assigned to this virtual NIC.
	MAC net.HardwareAddr

	// Bridge is the Linux bridge the NIC is attached to (e.g. "vmbr0",
	// "vnet0"). Empty if the VM uses user-mode networking.
	Bridge string

	// Firewall indicates whether PVE's firewall is enabled for this NIC.
	Firewall bool

	// Tag is the VLAN tag applied to packets on this NIC (0 means unset).
	Tag int

	// MTU overrides the NIC's MTU (0 means use bridge MTU; only valid for
	// virtio NICs).
	MTU int
}
