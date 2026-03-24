package openstack

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/vmconfig"
)

// fakeResolver returns a fixed VMRecord, ignoring ifname and ifindex.
type fakeResolver struct {
	rec *identity.VMRecord
}

func (f *fakeResolver) RecordByName(_ string, _ int32) (*identity.VMRecord, error) {
	return f.rec, nil
}

func makeMAC(s string) net.HardwareAddr {
	mac, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return mac
}

// testRecord returns a VMRecord representative of a typical Proxmox VM.
func testRecord() *identity.VMRecord {
	return &identity.VMRecord{
		Node:     "pve-node1",
		VMID:     100,
		NetIndex: 0,
		IfIndex:  3,
		Config: &vmconfig.VMConfig{
			Name:        "test-vm",
			OSType:      "l26",
			Description: "a test VM",
			Tags:        []string{"prod", "web"},
			Networks: map[int]vmconfig.NetworkDevice{
				0: {
					Model:  "virtio",
					MAC:    makeMAC("52:54:00:12:34:56"),
					Bridge: "vmbr0",
				},
				1: {
					Model:  "virtio",
					MAC:    makeMAC("52:54:00:ab:cd:ef"),
					Bridge: "vmbr1",
					MTU:    9000,
				},
			},
			Raw: map[string]string{
				"cores":  "2",
				"memory": "2048",
			},
		},
	}
}

// get issues a GET request against a handler built from rec and returns the response.
func get(t *testing.T, rec *identity.VMRecord, path string) *http.Response {
	t.Helper()
	resolver := &fakeResolver{rec: rec}
	handler := NewServer().NewHandler(resolver, "tap100i0", 3)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Result()
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b)
}

// ---------------------------------------------------------------------------
// Version listing
// ---------------------------------------------------------------------------

func TestVersionListing(t *testing.T) {
	resp := get(t, testRecord(), "/openstack")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	lines := strings.Fields(body(t, resp))
	assert.Contains(t, lines, "latest", "version listing must include 'latest'")
}

func TestVersionListingTrailingSlash(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body(t, resp), "latest")
}

// ---------------------------------------------------------------------------
// File listing
// ---------------------------------------------------------------------------

func TestFileListing(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	b := body(t, resp)
	assert.Contains(t, b, "meta_data.json")
	assert.Contains(t, b, "network_data.json")
	assert.Contains(t, b, "user_data")
}

// ---------------------------------------------------------------------------
// meta_data.json
// ---------------------------------------------------------------------------

func TestMetaDataUUID(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/meta_data.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var md MetaData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&md))

	assert.Equal(t, "100", md.UUID, "uuid must be the VMID")
}

func TestMetaDataHostname(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/meta_data.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var md MetaData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&md))

	assert.Equal(t, "test-vm", md.Hostname)
	assert.Equal(t, "test-vm", md.Name)
}

func TestMetaDataAvailabilityZone(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/meta_data.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var md MetaData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&md))

	assert.Equal(t, "pve-node1", md.AvailabilityZone)
}

func TestMetaDataLaunchIndex(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/meta_data.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var md MetaData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&md))

	assert.Equal(t, 0, md.LaunchIndex)
}

func TestMetaDataMetaContainsPVEKeys(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/meta_data.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var md MetaData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&md))

	assert.Equal(t, "100", md.Meta["pve:vmid"])
	assert.Equal(t, "pve-node1", md.Meta["pve:node"])
}

func TestMetaDataMetaContainsTags(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/meta_data.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var md MetaData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&md))

	// PVE bare tags appear as keys with empty values.
	_, hasProd := md.Meta["prod"]
	_, hasWeb := md.Meta["web"]
	assert.True(t, hasProd, "tag 'prod' should be present in meta")
	assert.True(t, hasWeb, "tag 'web' should be present in meta")
}

// ---------------------------------------------------------------------------
// network_data.json
// ---------------------------------------------------------------------------

func TestNetworkDataLinkCount(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/network_data.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var nd NetworkData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&nd))

	assert.Len(t, nd.Links, 2, "one link per NIC")
	assert.Len(t, nd.Networks, 2, "one network per NIC")
}

func TestNetworkDataLinksOrdered(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/network_data.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var nd NetworkData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&nd))

	// Indices must be sorted: net0 before net1.
	assert.Equal(t, "net0", nd.Links[0].ID)
	assert.Equal(t, "net1", nd.Links[1].ID)
}

func TestNetworkDataLinkType(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/network_data.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var nd NetworkData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&nd))

	for _, link := range nd.Links {
		assert.Equal(t, "phy", link.Type, "all links must be physical")
	}
}

func TestNetworkDataMACAddresses(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/network_data.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var nd NetworkData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&nd))

	macs := make(map[string]bool)
	for _, link := range nd.Links {
		macs[link.EthernetMACAddress] = true
	}
	assert.True(t, macs["52:54:00:12:34:56"], "net0 MAC should be present")
	assert.True(t, macs["52:54:00:ab:cd:ef"], "net1 MAC should be present")
}

func TestNetworkDataMTUZeroOmitted(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/network_data.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var nd NetworkData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&nd))

	// net0 has MTU=0 (default); the JSON field must be omitted (decodes as 0).
	assert.Equal(t, 0, nd.Links[0].MTU, "zero MTU should be omitted from JSON")
	// net1 has MTU=9000 explicitly set.
	assert.Equal(t, 9000, nd.Links[1].MTU)
}

func TestNetworkDataNetworksDHCP(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/network_data.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var nd NetworkData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&nd))

	for _, network := range nd.Networks {
		assert.Equal(t, "ipv4_dhcp", network.Type)
	}
}

func TestNetworkDataNetworksReferenceLinks(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/network_data.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var nd NetworkData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&nd))

	// Build link ID set.
	linkIDs := make(map[string]bool)
	for _, link := range nd.Links {
		linkIDs[link.ID] = true
	}
	// Every network's Link field must reference an existing link.
	for _, network := range nd.Networks {
		assert.True(t, linkIDs[network.Link], "network %q references unknown link %q", network.ID, network.Link)
	}
}

func TestNetworkDataServicesEmpty(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/network_data.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var nd NetworkData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&nd))

	assert.NotNil(t, nd.Services, "services must be a JSON array, not null")
	assert.Empty(t, nd.Services)
}

// ---------------------------------------------------------------------------
// user_data
// ---------------------------------------------------------------------------

func TestUserDataAbsent(t *testing.T) {
	rec := testRecord()
	rec.Config.Description = "no user-data here"
	resp := get(t, rec, "/openstack/latest/user_data")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestUserDataPresent(t *testing.T) {
	rec := testRecord()
	rec.Config.Description = "<!--#user-data\n#cloud-config\nhostname: test\n-->"
	resp := get(t, rec, "/openstack/latest/user_data")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body(t, resp), "#cloud-config")
}

// ---------------------------------------------------------------------------
// vendor_data
// ---------------------------------------------------------------------------

func TestVendorDataJSON(t *testing.T) {
	for _, path := range []string{
		"/openstack/latest/vendor_data.json",
		"/openstack/latest/vendor_data2.json",
	} {
		t.Run(path, func(t *testing.T) {
			resp := get(t, testRecord(), path)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

			// Must be valid JSON.
			var v any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&v))
		})
	}
}

// ---------------------------------------------------------------------------
// EC2 metadata shim
// ---------------------------------------------------------------------------

func TestEC2MetadataRootEmpty200(t *testing.T) {
	// cloud-init's OpenStack datasource calls _read_ec2_metadata(), which hits
	// /latest/meta-data/. We return an empty 200 so it treats ec2_metadata as
	// {} without producing errors or retrying.
	for _, path := range []string{"/latest/meta-data", "/latest/meta-data/"} {
		t.Run(path, func(t *testing.T) {
			resp := get(t, testRecord(), path)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Empty(t, body(t, resp))
		})
	}
}

// ---------------------------------------------------------------------------
// Unknown paths
// ---------------------------------------------------------------------------

func TestUnknownFileNotFound(t *testing.T) {
	resp := get(t, testRecord(), "/openstack/latest/no-such-file")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestNonOpenStackPathNotFound(t *testing.T) {
	resp := get(t, testRecord(), "/latest/meta-data/instance-id")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// Version agnosticism: any version string returns the same data
// ---------------------------------------------------------------------------

func TestAnyVersionAccepted(t *testing.T) {
	for _, version := range []string{"latest", "2018-08-27", "2012-08-10"} {
		t.Run(version, func(t *testing.T) {
			resp := get(t, testRecord(), "/openstack/"+version+"/meta_data.json")
			require.Equal(t, http.StatusOK, resp.StatusCode)

			var md MetaData
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&md))
			assert.Equal(t, "100", md.UUID)
		})
	}
}
