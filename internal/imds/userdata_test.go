package imds

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUserData_Basic(t *testing.T) {
	desc := "<!--#user-data\n#cloud-config\nusers:\n  - default\n-->\nother text"
	got, ok := ParseUserData(desc)
	require.True(t, ok)
	assert.Equal(t, "#cloud-config\nusers:\n  - default", got)
}

func TestParseUserData_NoMarker(t *testing.T) {
	_, ok := ParseUserData("just a plain description")
	assert.False(t, ok)
}

func TestParseUserData_NoClosingTag(t *testing.T) {
	_, ok := ParseUserData("<!--#user-data\n#cloud-config\n")
	assert.False(t, ok)
}

func TestParseUserData_EmptyContent(t *testing.T) {
	// Whitespace-only content between the tags is treated as absent.
	_, ok := ParseUserData("<!--#user-data\n   \n-->")
	assert.False(t, ok)
}

func TestParseUserData_WhitespaceStripped(t *testing.T) {
	desc := "<!--#user-data\n\n  #cloud-config\n\n-->"
	got, ok := ParseUserData(desc)
	require.True(t, ok)
	assert.Equal(t, "#cloud-config", got)
}

func TestParseUserData_ContentContainsClosingTag(t *testing.T) {
	// The user-data body itself contains "-->". The parser must use the LAST
	// occurrence of "-->" as the end of the block, not the first.
	desc := "<!--#user-data\n# yaml comment --> still user-data\nruncmd: []\n-->\nignored"
	got, ok := ParseUserData(desc)
	require.True(t, ok)
	assert.Equal(t, "# yaml comment --> still user-data\nruncmd: []", got)
}

func TestParseUserData_TextBeforeMarker(t *testing.T) {
	// Text before the opening tag is ignored.
	desc := "human-readable summary\n\n<!--#user-data\n#cloud-config\n-->"
	got, ok := ParseUserData(desc)
	require.True(t, ok)
	assert.Equal(t, "#cloud-config", got)
}

func TestParseUserData_EmptyDescription(t *testing.T) {
	_, ok := ParseUserData("")
	assert.False(t, ok)
}
