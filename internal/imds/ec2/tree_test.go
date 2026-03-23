package ec2

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --------------------------------------------------------------------------
// Leaf nodes
// --------------------------------------------------------------------------

func TestLeafLookup(t *testing.T) {
	tree := buildTree(InstanceMetadata{InstanceID: "i-00000064"})

	node, ok := tree.lookup("instance-id")
	require.True(t, ok, "instance-id should exist")
	require.NotNil(t, node.value)
	assert.Equal(t, "i-00000064", *node.value)
}

func TestLeafLookupTrailingSlash(t *testing.T) {
	// A trailing slash on a leaf should still resolve to the leaf.
	tree := buildTree(InstanceMetadata{InstanceID: "i-1"})

	node, ok := tree.lookup("instance-id/")
	require.True(t, ok)
	require.NotNil(t, node.value)
	assert.Equal(t, "i-1", *node.value)
}

func TestEmptyStringFieldOmitted(t *testing.T) {
	// A zero-value string field must not appear in the tree.
	tree := buildTree(InstanceMetadata{
		InstanceID: "i-1",
		LocalIPv4:  "", // explicitly absent
	})

	_, ok := tree.lookup("local-ipv4")
	assert.False(t, ok, "empty string fields must return 404")
}

func TestMissingPathNotFound(t *testing.T) {
	tree := buildTree(InstanceMetadata{InstanceID: "i-1"})

	_, ok := tree.lookup("no-such-key")
	assert.False(t, ok)
}

// --------------------------------------------------------------------------
// Static directory nodes
// --------------------------------------------------------------------------

func TestRootListing(t *testing.T) {
	tree := buildTree(InstanceMetadata{
		InstanceID: "i-1",
		Hostname:   "vm.local",
	})

	root, ok := tree.lookup("")
	require.True(t, ok)
	listing := root.listing()

	assert.Contains(t, listing, "instance-id\n")
	assert.Contains(t, listing, "hostname\n")
	// Empty fields must not appear.
	assert.NotContains(t, listing, "local-ipv4")
}

func TestSubdirLookup(t *testing.T) {
	tree := buildTree(InstanceMetadata{
		Placement: PlacementMetadata{
			AvailabilityZone: "pve-node1",
			Region:           "proxmox",
		},
	})

	// placement is a directory
	pNode, ok := tree.lookup("placement")
	require.True(t, ok, "placement should be reachable")
	assert.Nil(t, pNode.value, "placement should be a directory, not a leaf")

	// placement/availability-zone is a leaf
	azNode, ok := tree.lookup("placement/availability-zone")
	require.True(t, ok)
	require.NotNil(t, azNode.value)
	assert.Equal(t, "pve-node1", *azNode.value)

	// placement/region is a leaf
	regionNode, ok := tree.lookup("placement/region")
	require.True(t, ok)
	require.NotNil(t, regionNode.value)
	assert.Equal(t, "proxmox", *regionNode.value)
}

func TestSubdirListing(t *testing.T) {
	tree := buildTree(InstanceMetadata{
		Placement: PlacementMetadata{
			AvailabilityZone: "pve-node1",
			Region:           "proxmox",
		},
	})

	pNode, ok := tree.lookup("placement")
	require.True(t, ok)

	listing := pNode.listing()
	assert.Contains(t, listing, "availability-zone\n")
	assert.Contains(t, listing, "region\n")
	// Must end with a newline.
	assert.True(t, strings.HasSuffix(listing, "\n"))
}

func TestSubdirListingShowsDirectorySuffix(t *testing.T) {
	// The root listing must show "placement/" (trailing slash) because
	// placement is a directory, not a leaf.
	tree := buildTree(InstanceMetadata{
		InstanceID: "i-1",
		Placement: PlacementMetadata{
			AvailabilityZone: "az1",
		},
	})

	root, ok := tree.lookup("")
	require.True(t, ok)
	listing := root.listing()

	assert.Contains(t, listing, "placement/\n")
	assert.Contains(t, listing, "instance-id\n") // no trailing slash for leaf
}

// --------------------------------------------------------------------------
// Map with string values (tags/instance/{tag-key})
// --------------------------------------------------------------------------

func TestStringMapListing(t *testing.T) {
	tree := buildTree(InstanceMetadata{
		Tags: map[string]string{
			"Name": "my-vm",
			"env":  "prod",
		},
	})

	// The directory at tags/instance lists all tag keys.
	node, ok := tree.lookup("tags/instance")
	require.True(t, ok, "tags/instance should be reachable")
	listing := node.listing()
	assert.Contains(t, listing, "Name\n")
	assert.Contains(t, listing, "env\n")
}

func TestStringMapLeaf(t *testing.T) {
	tree := buildTree(InstanceMetadata{
		Tags: map[string]string{"Name": "my-vm"},
	})

	node, ok := tree.lookup("tags/instance/Name")
	require.True(t, ok, "tags/instance/Name should be reachable")
	require.NotNil(t, node.value)
	assert.Equal(t, "my-vm", *node.value)
}

func TestStringMapMissingKey(t *testing.T) {
	tree := buildTree(InstanceMetadata{
		Tags: map[string]string{"Name": "my-vm"},
	})

	_, ok := tree.lookup("tags/instance/no-such-tag")
	assert.False(t, ok, "missing tag key should return 404")
}

func TestNilStringMapOmitted(t *testing.T) {
	// A nil Tags map must not expose a tags/ sub-tree.
	tree := buildTree(InstanceMetadata{
		InstanceID: "i-1",
		Tags:       nil,
	})

	_, ok := tree.lookup("tags")
	assert.False(t, ok, "nil map should not create a tags sub-tree")
}

// --------------------------------------------------------------------------
// Map with struct values (network/interfaces/macs/{mac})
// --------------------------------------------------------------------------

func TestStructMapDirectoryListing(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:ff"
	tree := buildTree(InstanceMetadata{
		Network: NetworkMetadata{
			Interfaces: NetworkInterfacesMetadata{
				MACs: map[string]MACMetadata{
					mac: {DeviceNumber: "0", MAC: mac},
				},
			},
		},
	})

	macsNode, ok := tree.lookup("network/interfaces/macs")
	require.True(t, ok, "network/interfaces/macs should be reachable")
	assert.Contains(t, macsNode.listing(), mac+"/")
}

func TestStructMapLeaf(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:ff"
	tree := buildTree(InstanceMetadata{
		Network: NetworkMetadata{
			Interfaces: NetworkInterfacesMetadata{
				MACs: map[string]MACMetadata{
					mac: {DeviceNumber: "0", MAC: mac},
				},
			},
		},
	})

	devNode, ok := tree.lookup("network/interfaces/macs/" + mac + "/device-number")
	require.True(t, ok, "device-number should be reachable")
	require.NotNil(t, devNode.value)
	assert.Equal(t, "0", *devNode.value)
}

func TestStructMapEmptyFieldsOmitted(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:ff"
	tree := buildTree(InstanceMetadata{
		Network: NetworkMetadata{
			Interfaces: NetworkInterfacesMetadata{
				MACs: map[string]MACMetadata{
					// local-ipv4s is deliberately zero-value.
					mac: {DeviceNumber: "0", MAC: mac},
				},
			},
		},
	})

	_, ok := tree.lookup("network/interfaces/macs/" + mac + "/local-ipv4s")
	assert.False(t, ok, "empty MACMetadata.LocalIPv4s should not be served")
}

func TestStructMapUnknownMACNotFound(t *testing.T) {
	tree := buildTree(InstanceMetadata{
		Network: NetworkMetadata{
			Interfaces: NetworkInterfacesMetadata{
				MACs: map[string]MACMetadata{
					"aa:bb:cc:dd:ee:ff": {DeviceNumber: "0"},
				},
			},
		},
	})

	_, ok := tree.lookup("network/interfaces/macs/00:00:00:00:00:00")
	assert.False(t, ok, "unknown MAC should return 404")
}

// --------------------------------------------------------------------------
// Listing sort order
// --------------------------------------------------------------------------

func TestListingIsSorted(t *testing.T) {
	tree := buildTree(InstanceMetadata{
		Tags: map[string]string{
			"zebra": "z",
			"alpha": "a",
			"mango": "m",
		},
	})

	node, ok := tree.lookup("tags/instance")
	require.True(t, ok)
	items := strings.Split(strings.TrimRight(node.listing(), "\n"), "\n")
	require.Len(t, items, 3)
	assert.Equal(t, []string{"alpha", "mango", "zebra"}, items)
}
