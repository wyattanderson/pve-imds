package vmconfig

import (
	"crypto/sha256"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustMAC(s string) net.HardwareAddr {
	mac, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return mac
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return raw
}

// TestPlain covers a single-net-device config with tags and a description.
func TestPlain(t *testing.T) {
	raw := readFixture(t, "plain.conf")
	cfg, err := ParseConfig(raw)
	require.NoError(t, err)

	assert.Equal(t, "apache", cfg.Name)
	assert.Equal(t, "l26", cfg.OSType)
	assert.Equal(t, "simple Linux VM", cfg.Description)
	assert.Equal(t, []string{"production", "web"}, cfg.Tags)

	require.Len(t, cfg.Networks, 1)
	net0 := cfg.Networks[0]
	assert.Equal(t, "virtio", net0.Model)
	assert.Equal(t, "92:38:11:fd:ed:87", net0.MAC.String())
	assert.Equal(t, "vmbr0", net0.Bridge)
	assert.True(t, net0.Firewall)

	assert.Equal(t, "1", cfg.Raw["cores"])
	assert.Equal(t, "512", cfg.Raw["memory"])

	assert.Equal(t, sha256.Sum256(raw), cfg.Digest)
}

// TestMultiNet covers three net devices with VLAN tag and MTU options.
func TestMultiNet(t *testing.T) {
	raw := readFixture(t, "multi_net.conf")
	cfg, err := ParseConfig(raw)
	require.NoError(t, err)

	require.Len(t, cfg.Networks, 3)

	cases := []struct {
		idx      int
		model    string
		mac      string
		bridge   string
		firewall bool
		tag      int
		mtu      int
	}{
		{0, "virtio", "bc:24:11:a3:da:b1", "vnet0", true, 0, 0},
		{1, "e1000", "bc:24:11:79:d5:65", "vnet0", true, 100, 0},
		{2, "vmxnet3", "de:ad:be:ef:ca:fe", "vmbr0", false, 0, 9000},
	}
	for _, tc := range cases {
		dev, ok := cfg.Networks[tc.idx]
		require.True(t, ok, "Networks[%d] missing", tc.idx)
		assert.Equal(t, tc.model, dev.Model, "Networks[%d].Model", tc.idx)
		assert.Equal(t, tc.mac, dev.MAC.String(), "Networks[%d].MAC", tc.idx)
		assert.Equal(t, tc.bridge, dev.Bridge, "Networks[%d].Bridge", tc.idx)
		assert.Equal(t, tc.firewall, dev.Firewall, "Networks[%d].Firewall", tc.idx)
		assert.Equal(t, tc.tag, dev.Tag, "Networks[%d].Tag", tc.idx)
		assert.Equal(t, tc.mtu, dev.MTU, "Networks[%d].MTU", tc.idx)
	}

	assert.Equal(t, []string{"windows", "prod", "tier-1"}, cfg.Tags)
}

// TestSectionsIgnored verifies that [PENDING], [special:cloudinit], and snapshot
// sections are not parsed into the main config.
func TestSectionsIgnored(t *testing.T) {
	raw := readFixture(t, "sections.conf")
	cfg, err := ParseConfig(raw)
	require.NoError(t, err)

	assert.NotContains(t, cfg.Raw, "bios", "[PENDING] section should be ignored")
	assert.NotContains(t, cfg.Raw, "snaptime", "snapshot section should be ignored")

	require.Len(t, cfg.Networks, 1)
	assert.Equal(t, "bc:24:11:2c:69:ec", cfg.Networks[0].MAC.String())
	assert.Equal(t, []string{"staging", "linux"}, cfg.Tags)
}

// TestNoNet verifies a config with no net devices produces an empty Networks map.
func TestNoNet(t *testing.T) {
	raw := readFixture(t, "no_net.conf")
	cfg, err := ParseConfig(raw)
	require.NoError(t, err)

	assert.Empty(t, cfg.Networks)
	assert.Nil(t, cfg.Tags)
}

// TestTagParsing exercises the tag splitting logic directly.
func TestTagParsing(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"foo;bar;baz", []string{"foo", "bar", "baz"}},
		{"single", []string{"single"}},
		{" foo ; bar ", []string{"foo", "bar"}}, // whitespace trimmed
		{"", nil},                               // empty → nil
		{";;", nil},                             // only separators → nil
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, parseTags(tc.input), "parseTags(%q)", tc.input)
	}
}

// TestDigestCoversEntireFile verifies that the digest changes when content
// beyond the main section is modified.
func TestDigestCoversEntireFile(t *testing.T) {
	raw := readFixture(t, "sections.conf")
	cfg, err := ParseConfig(raw)
	require.NoError(t, err)

	modified := append(append([]byte{}, raw...), '\n')
	cfg2, err := ParseConfig(modified)
	require.NoError(t, err)

	assert.NotEqual(t, cfg.Digest, cfg2.Digest)
}

// TestEncodedDescription verifies that a percent-encoded description: value is decoded.
func TestEncodedDescription(t *testing.T) {
	raw := readFixture(t, "encoded_desc.conf")
	cfg, err := ParseConfig(raw)
	require.NoError(t, err)

	want := "#cloud-config\nfinal_message: cloud-init complete\nfqdn: imdstest01.lab.wya.tt"
	assert.Equal(t, want, cfg.Description)
}

// TestCommentDescriptionDecoded verifies that percent-encoded characters in
// comment-accumulated descriptions are decoded, covering the case where user-data
// is embedded in the VM description via comment lines.
func TestCommentDescriptionDecoded(t *testing.T) {
	raw := []byte(
		"#<!--#user-data\n" +
			"##cloud-config\n" +
			"#final_message%3A cloud-init complete\n" +
			"#fqdn%3A imdstest01.lab.wya.tt\n" +
			"#package_upgrade%3A true\n" +
			"#-->\n" +
			"name: imdstest01\n",
	)
	cfg, err := ParseConfig(raw)
	require.NoError(t, err)

	want := "<!--#user-data\n#cloud-config\nfinal_message: cloud-init complete\nfqdn: imdstest01.lab.wya.tt\npackage_upgrade: true\n-->"
	assert.Equal(t, want, cfg.Description)
}

// TestCommentDescriptionIndentation verifies that leading spaces in comment lines
// are preserved exactly. Proxmox writes '#' + content with no separator space, so
// stripping only '#' must leave all indentation intact for embedded YAML.
func TestCommentDescriptionIndentation(t *testing.T) {
	raw := []byte(
		"#<!--#user-data\n" +
			"##cloud-config\n" +
			"#write_files%3A\n" +
			"#- content%3A Hello\n" +
			"#  owner%3A root%3Aroot\n" +
			"#  permissions%3A '0644'\n" +
			"#-->\n" +
			"name: imdstest01\n",
	)
	cfg, err := ParseConfig(raw)
	require.NoError(t, err)

	want := "<!--#user-data\n#cloud-config\nwrite_files:\n- content: Hello\n  owner: root:root\n  permissions: '0644'\n-->"
	assert.Equal(t, want, cfg.Description)
}

// TestParseSMBIOS exercises parseSMBIOS directly.
func TestParseSMBIOS(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    map[string]string
		wantErr bool
	}{
		{
			name:  "uuid only",
			input: "uuid=86f5aa5e-08a3-40cb-a642-efad20b5b061",
			want:  map[string]string{"uuid": "86f5aa5e-08a3-40cb-a642-efad20b5b061"},
		},
		{
			name:  "uuid with base64 product",
			input: "uuid=86f5aa5e-08a3-40cb-a642-efad20b5b061,product=T3BlblN0YWNrIE5vdmE=,base64=1",
			want: map[string]string{
				"uuid":    "86f5aa5e-08a3-40cb-a642-efad20b5b061",
				"product": "OpenStack Nova",
			},
		},
		{
			name:  "no base64 flag leaves values as-is",
			input: "uuid=86f5aa5e-08a3-40cb-a642-efad20b5b061,product=OpenStack Nova",
			want: map[string]string{
				"uuid":    "86f5aa5e-08a3-40cb-a642-efad20b5b061",
				"product": "OpenStack Nova",
			},
		},
		{
			name:    "invalid base64 value",
			input:   "uuid=86f5aa5e-08a3-40cb-a642-efad20b5b061,product=!!!,base64=1",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSMBIOS(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestParseSMBIOS1Key verifies that a smbios1 config key is parsed into VMConfig.SMBIOS.
func TestParseSMBIOS1Key(t *testing.T) {
	raw := []byte("name: myvm\nsmbios1: uuid=86f5aa5e-08a3-40cb-a642-efad20b5b061,product=T3BlblN0YWNrIE5vdmE=,base64=1\n")
	cfg, err := ParseConfig(raw)
	require.NoError(t, err)

	require.NotNil(t, cfg.SMBIOS)
	assert.Equal(t, "86f5aa5e-08a3-40cb-a642-efad20b5b061", cfg.SMBIOS["uuid"])
	assert.Equal(t, "OpenStack Nova", cfg.SMBIOS["product"])
	assert.NotContains(t, cfg.Raw, "smbios1", "smbios1 must not appear in Raw")
}

// TestNoSMBIOS verifies that a config without smbios1 leaves VMConfig.SMBIOS nil.
func TestNoSMBIOS(t *testing.T) {
	raw := []byte("name: myvm\n")
	cfg, err := ParseConfig(raw)
	require.NoError(t, err)
	assert.Nil(t, cfg.SMBIOS)
}

// TestMalformedNet verifies that a net entry with no '=' returns an error.
func TestMalformedNet(t *testing.T) {
	_, err := ParseConfig([]byte("net0: virtioNOEQUALS,bridge=vmbr0\n"))
	assert.Error(t, err)
}

// TestMalformedMAC verifies that a net entry with an invalid MAC returns an error.
func TestMalformedMAC(t *testing.T) {
	_, err := ParseConfig([]byte("net0: virtio=ZZ:ZZ:ZZ:ZZ:ZZ:ZZ,bridge=vmbr0\n"))
	assert.Error(t, err)
}

// TestParseNetworkDevice exercises the network device parser directly.
func TestParseNetworkDevice(t *testing.T) {
	cases := []struct {
		input   string
		want    NetworkDevice
		wantErr bool
	}{
		{
			input: "virtio=BC:24:11:2C:69:EC,bridge=vnet0,firewall=1",
			want: NetworkDevice{
				Model:    "virtio",
				MAC:      mustMAC("BC:24:11:2C:69:EC"),
				Bridge:   "vnet0",
				Firewall: true,
			},
		},
		{
			input: "e1000=DE:AD:BE:EF:00:01,bridge=vmbr0,tag=100,mtu=1500",
			want: NetworkDevice{
				Model:  "e1000",
				MAC:    mustMAC("DE:AD:BE:EF:00:01"),
				Bridge: "vmbr0",
				Tag:    100,
				MTU:    1500,
			},
		},
		{
			// No bridge: user-mode networking
			input: "virtio=AA:BB:CC:DD:EE:FF",
			want: NetworkDevice{
				Model: "virtio",
				MAC:   mustMAC("AA:BB:CC:DD:EE:FF"),
			},
		},
		{input: "noequals", wantErr: true},
		{input: "virtio=not-a-mac", wantErr: true},
	}

	for _, tc := range cases {
		dev, err := parseNetworkDevice(tc.input)
		if tc.wantErr {
			assert.Error(t, err, "parseNetworkDevice(%q)", tc.input)
			continue
		}
		require.NoError(t, err, "parseNetworkDevice(%q)", tc.input)
		assert.Equal(t, tc.want.Model, dev.Model, "Model")
		assert.Equal(t, tc.want.MAC.String(), dev.MAC.String(), "MAC")
		assert.Equal(t, tc.want.Bridge, dev.Bridge, "Bridge")
		assert.Equal(t, tc.want.Firewall, dev.Firewall, "Firewall")
		assert.Equal(t, tc.want.Tag, dev.Tag, "Tag")
		assert.Equal(t, tc.want.MTU, dev.MTU, "MTU")
	}
}
