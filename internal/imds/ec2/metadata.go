package ec2

import (
	"fmt"
	"strconv"

	"github.com/wyattanderson/pve-imds/internal/identity"
)

// InstanceMetadata holds the complete metadata tree served at
// /{version}/meta-data/.
//
// Each exported field carries an `imds` struct tag that describes its URL
// path relative to the meta-data root. The routing rules are:
//
//   - string field        — leaf at the given path; empty strings are omitted
//     (excluded from directory listings, return 404).
//   - struct field        — directory at the given path; the struct's own
//     `imds`-tagged fields become its sub-paths.
//   - map[string]string   — the tag must end with a {placeholder} segment.
//     The path before {placeholder} is a dynamic
//     directory whose children are the map keys and
//     whose leaf values are the map values.
//   - map[string]T        — same, but T is a struct whose own tags define the
//     sub-paths under each key.
//
// Fields tagged `imds:"-"` are excluded entirely.
type InstanceMetadata struct {
	// --- Identity ---

	// AMIID maps loosely to the VM's identifier. Provisioned as "pve-{vmid}".
	AMIID string `imds:"ami-id"`

	// AMILaunchIndex is always "0"; Proxmox launches one instance at a time.
	AMILaunchIndex string `imds:"ami-launch-index"`

	// AMIManifestPath has no Proxmox equivalent; set to "(unknown)".
	AMIManifestPath string `imds:"ami-manifest-path"`

	// Hostname is the VM name from the PVE config.
	Hostname string `imds:"hostname"`

	// InstanceID is the Proxmox VMID as a decimal string.
	InstanceID string `imds:"instance-id"`

	// InstanceType encodes CPU/memory from the VM config. Formatted as
	// "proxmox.{cores}c.{memory}m" for now; subject to change.
	InstanceType string `imds:"instance-type"`

	// InstanceLifeCycle is always "on-demand" for Proxmox VMs.
	InstanceLifeCycle string `imds:"instance-life-cycle"`

	// LocalHostname is the VM name from the PVE config.
	LocalHostname string `imds:"local-hostname"`

	// LocalIPv4 is the VM's primary private IP. Empty until the IMDS service
	// can obtain IP information (DHCP lease data or static config).
	LocalIPv4 string `imds:"local-ipv4"`

	// MAC is the hardware address of the NIC that initiated the request
	// (i.e. the NIC with index NetIndex in the VM config).
	MAC string `imds:"mac"`

	// ReservationID has no Proxmox equivalent; formatted "r-{vmid}".
	ReservationID string `imds:"reservation-id"`

	// --- Sub-trees ---

	// Placement describes the VM's location within the Proxmox cluster.
	Placement PlacementMetadata `imds:"placement"`

	// Network describes all virtual NICs attached to the VM.
	Network NetworkMetadata `imds:"network"`

	// Tags are key/value pairs for this instance, synthesised from the VM's
	// PVE name, VMID, and tag list.
	// GET /tags/instance       → newline-separated list of tag keys
	// GET /tags/instance/{key} → value for that key
	Tags map[string]string `imds:"tags/instance/{tag-key}"`
}

// PlacementMetadata describes the virtual topology of the instance.
type PlacementMetadata struct {
	// AvailabilityZone maps to the Proxmox node name. In a cluster each node
	// acts as a distinct AZ. May be overridden by static hypervisor config.
	AvailabilityZone string `imds:"availability-zone"`

	// Region is a static value configured on the hypervisor. Defaults to
	// "proxmox" until an external-config layer is introduced.
	Region string `imds:"region"`
}

// NetworkMetadata is the root of the /network/ sub-tree.
type NetworkMetadata struct {
	Interfaces NetworkInterfacesMetadata `imds:"interfaces"`
}

// NetworkInterfacesMetadata holds per-NIC metadata keyed by MAC address.
type NetworkInterfacesMetadata struct {
	// MACs maps each NIC's MAC address to its per-interface metadata.
	// GET /network/interfaces/macs              → list of MAC addresses
	// GET /network/interfaces/macs/{mac}/...    → per-NIC fields
	MACs map[string]MACMetadata `imds:"macs/{mac}"`
}

// MACMetadata holds the IMDS fields for a single virtual network interface.
// Field names and semantics follow the EC2 IMDS convention.
type MACMetadata struct {
	// DeviceNumber is the NIC index within the VM (the N in netN).
	DeviceNumber string `imds:"device-number"`

	// InterfaceID has no Proxmox equivalent. Left empty for now.
	InterfaceID string `imds:"interface-id"`

	// LocalHostname mirrors the instance-level local-hostname.
	LocalHostname string `imds:"local-hostname"`

	// LocalIPv4s is the NIC's private IP(s). Empty until IP info is available.
	LocalIPv4s string `imds:"local-ipv4s"`

	// MAC is this interface's hardware address.
	MAC string `imds:"mac"`

	// PublicHostname is empty for Proxmox VMs (no public DNS by default).
	PublicHostname string `imds:"public-hostname"`

	// PublicIPv4s is empty for Proxmox VMs.
	PublicIPv4s string `imds:"public-ipv4s"`

	// SecurityGroups has no Proxmox equivalent. Left empty for now.
	SecurityGroups string `imds:"security-groups"`

	// SecurityGroupIDs has no Proxmox equivalent. Left empty for now.
	SecurityGroupIDs string `imds:"security-group-ids"`

	// SubnetID has no Proxmox equivalent. Left empty for now.
	SubnetID string `imds:"subnet-id"`

	// SubnetIPv4CIDRBlock is empty until subnet information is available.
	SubnetIPv4CIDRBlock string `imds:"subnet-ipv4-cidr-block"`

	// VpcID has no Proxmox equivalent. Left empty for now.
	VpcID string `imds:"vpc-id"`
}

// MetadataFromRecord builds an InstanceMetadata from a resolved VMRecord.
//
// This function maps the fields directly derivable from a VMRecord. Fields
// that require additional context not present in VMRecord — real IP addresses,
// externally-configured region names, VPC/subnet identifiers — are left empty
// or given conservative placeholder values. They are expected to be filled in
// once a configuration layer is introduced.
func MetadataFromRecord(rec *identity.VMRecord) InstanceMetadata {
	hostname := rec.Config.Name

	// MAC of the requesting NIC (identified by NetIndex from the tap name).
	mac := ""
	if nic, ok := rec.Config.Networks[rec.NetIndex]; ok {
		mac = nic.MAC.String()
	}

	// Per-NIC entries for /network/interfaces/macs/{mac}/.
	// We populate all NICs from the config, not just the requesting one,
	// because cloud-init uses the full NIC list to configure networking.
	macs := make(map[string]MACMetadata, len(rec.Config.Networks))
	for idx, nic := range rec.Config.Networks {
		macs[nic.MAC.String()] = MACMetadata{
			DeviceNumber:  strconv.Itoa(idx),
			MAC:           nic.MAC.String(),
			LocalHostname: hostname,
		}
	}

	// Instance tags: synthesised from PVE name/VMID/tags.
	// PVE tags are bare labels, so we expose them with an empty value.
	// cloud-init typically looks for "Name" and user-defined keys.
	tags := map[string]string{
		"Name":     rec.Config.Name,
		"pve:vmid": strconv.Itoa(rec.VMID),
		"pve:node": rec.Node,
	}
	for _, t := range rec.Config.Tags {
		tags[t] = ""
	}

	return InstanceMetadata{
		AMIID:             fmt.Sprintf("pve-%d", rec.VMID),
		AMILaunchIndex:    "0",
		AMIManifestPath:   "(unknown)",
		Hostname:          hostname,
		InstanceID:        strconv.Itoa(rec.VMID),
		InstanceType:      instanceType(rec),
		InstanceLifeCycle: "on-demand",
		LocalHostname:     hostname,
		MAC:               mac,
		ReservationID:     fmt.Sprintf("r-%d", rec.VMID),
		Placement: PlacementMetadata{
			AvailabilityZone: rec.Node,
			Region:           "proxmox",
		},
		Network: NetworkMetadata{
			Interfaces: NetworkInterfacesMetadata{
				MACs: macs,
			},
		},
		Tags: tags,
	}
}

// instanceType derives a pseudo instance-type string from the VM config.
// Format: "proxmox.{cores}c.{memory_mb}m", e.g. "proxmox.4c.2048m".
// Falls back to "proxmox.vm" when the raw config keys are absent.
func instanceType(rec *identity.VMRecord) string {
	cores := rec.Config.Raw["cores"]
	memory := rec.Config.Raw["memory"]
	if cores == "" || memory == "" {
		return "proxmox.vm"
	}
	return fmt.Sprintf("proxmox.%sc.%sm", cores, memory)
}
