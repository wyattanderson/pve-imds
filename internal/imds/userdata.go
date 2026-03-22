package imds

import "strings"

const userDataOpenTag = "<!--#user-data"
const userDataCloseTag = "-->"

// ParseUserData extracts embedded user-data from a Proxmox VM description.
//
// User-data is declared with an HTML comment block starting with the literal
// text "<!--#user-data" and ending at the last occurrence of "-->":
//
//	<!--#user-data
//	#cloud-config
//	users:
//	  - default
//	-->
//	other unparsed text
//
// The content between the opening tag and the last "-->" is stripped of
// leading and trailing whitespace and returned. Using the last occurrence of
// "-->" rather than the first allows the user-data body to contain "-->"
// sequences without prematurely ending the block.
//
// Returns ("", false) when no opening tag is present, no closing "-->" follows
// the opening tag, or the trimmed content is empty.
func ParseUserData(description string) (string, bool) {
	// Cut discards everything before (and including) the opening tag.
	_, after, ok := strings.Cut(description, userDataOpenTag)
	if !ok {
		return "", false
	}

	end := strings.LastIndex(after, userDataCloseTag)
	if end < 0 {
		return "", false
	}

	userData := strings.TrimSpace(after[:end])
	if userData == "" {
		return "", false
	}

	return userData, true
}
