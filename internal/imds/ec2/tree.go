package ec2

import (
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
)

// treeNode is a node in the IMDS path tree. A node is either:
//   - a leaf: value != nil, no children
//   - a static directory: children != nil (may be empty if all sub-fields
//     were omitted), no value
//   - a dynamic directory: mapKeys + mapChild != nil; children may also be
//     non-nil if there are static siblings
//
// Nodes with none of the above set are unreachable and treated as 404.
type treeNode struct {
	// value is the response body for leaf nodes.
	value *string

	// children maps static path segments to child nodes.
	children map[string]*treeNode

	// mapKeys enumerates the dynamic key names present at this node.
	// Non-nil only for dynamic-directory nodes (map fields).
	mapKeys func() []string

	// mapChild returns the subtree for a given dynamic key, or nil if absent.
	// Non-nil only for dynamic-directory nodes.
	mapChild func(key string) *treeNode
}

func newDirNode() *treeNode {
	return &treeNode{children: make(map[string]*treeNode)}
}

// navigate follows (and creates as needed) the chain of static path segments
// from n and returns the terminal node.
func (n *treeNode) navigate(segments []string) *treeNode {
	cur := n
	for _, seg := range segments {
		if cur.children == nil {
			cur.children = make(map[string]*treeNode)
		}
		child, ok := cur.children[seg]
		if !ok {
			child = newDirNode()
			cur.children[seg] = child
		}
		cur = child
	}
	return cur
}

// lookup returns the node reached by following path from n.
// path is slash-separated; an empty string or "/" returns n itself.
// Reports false if any segment has no matching child.
func (n *treeNode) lookup(path string) (*treeNode, bool) {
	path = strings.Trim(path, "/")
	if path == "" {
		return n, true
	}
	cur := n
	for seg := range strings.SplitSeq(path, "/") {
		if seg == "" {
			continue
		}
		if cur.children != nil {
			if child, ok := cur.children[seg]; ok {
				cur = child
				continue
			}
		}
		if cur.mapChild != nil {
			if child := cur.mapChild(seg); child != nil {
				cur = child
				continue
			}
		}
		return nil, false
	}
	return cur, true
}

// listing returns the EC2-style directory listing for n: a newline-separated
// list of child names. Sub-directory names have a trailing "/". The result
// always ends with a newline. Items are sorted alphabetically.
func (n *treeNode) listing() string {
	var items []string
	for k, child := range n.children {
		if child.value != nil {
			items = append(items, k)
		} else {
			items = append(items, k+"/")
		}
	}
	if n.mapKeys != nil && n.mapChild != nil {
		for _, k := range n.mapKeys() {
			child := n.mapChild(k)
			if child != nil && child.value != nil {
				items = append(items, k)
			} else {
				items = append(items, k+"/")
			}
		}
	}
	sort.Strings(items)
	return strings.Join(items, "\n") + "\n"
}

// isPlaceholder reports whether s is a {placeholder} tag segment.
func isPlaceholder(s string) bool {
	return len(s) >= 3 && s[0] == '{' && s[len(s)-1] == '}'
}

// buildTree constructs the IMDS tree for the given InstanceMetadata by
// reflecting over `imds` struct tags.
func buildTree(md InstanceMetadata) *treeNode {
	root := newDirNode()
	populateNode(root, reflect.ValueOf(md))
	return root
}

// populateNode walks struct value v and attaches its `imds`-tagged fields as
// children of n. Struct fields recurse; map fields with a {placeholder} tag
// suffix create dynamic-directory nodes.
func populateNode(n *treeNode, v reflect.Value) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("imds")
		if tag == "" || tag == "-" {
			continue
		}
		attachField(n, tag, v.Field(i))
	}
}

// attachField attaches field value fv at the path described by tag onto root.
func attachField(root *treeNode, tag string, fv reflect.Value) {
	segments := strings.Split(tag, "/")

	if isPlaceholder(segments[len(segments)-1]) {
		// Map field: navigate to the directory node that precedes the dynamic
		// segment, then install the map's keys/values as its dynamic children.
		// Guard before navigating so a nil map creates no intermediate nodes.
		if fv.IsNil() {
			return
		}
		parent := root.navigate(segments[:len(segments)-1])
		attachMap(parent, fv)
		return
	}

	// Empty string fields are excluded from the tree entirely: they do not
	// appear in directory listings and return 404 when requested directly.
	// Check before navigating so that no intermediate nodes are created.
	if fv.Kind() == reflect.String && fv.String() == "" {
		return
	}

	target := root.navigate(segments)

	switch fv.Kind() {
	case reflect.String:
		s := fv.String()
		// Turn the node into a leaf (clear any directory state that navigate
		// may have set on a previously-visited node with the same path).
		target.children = nil
		target.mapKeys = nil
		target.mapChild = nil
		target.value = &s

	case reflect.Struct:
		populateNode(target, fv)
	}
}

// attachMap wires map field fv to node n, making it a dynamic directory.
// fv must be a map[string]V where V is either string or a struct type.
func attachMap(n *treeNode, fv reflect.Value) {
	if fv.IsNil() {
		return
	}
	elemKind := fv.Type().Elem().Kind()

	n.mapKeys = func() []string {
		if fv.IsNil() {
			return nil
		}
		keys := make([]string, 0, fv.Len())
		for _, k := range fv.MapKeys() {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return keys
	}

	switch elemKind {
	case reflect.String:
		n.mapChild = func(key string) *treeNode {
			mv := fv.MapIndex(reflect.ValueOf(key))
			if !mv.IsValid() {
				return nil
			}
			s := mv.String()
			return &treeNode{value: &s}
		}
	case reflect.Struct:
		n.mapChild = func(key string) *treeNode {
			mv := fv.MapIndex(reflect.ValueOf(key))
			if !mv.IsValid() {
				return nil
			}
			child := newDirNode()
			populateNode(child, mv)
			return child
		}
	}
}

// serveTree handles /{version}/meta-data/... requests.
// metaPath is the URL path with the version and "/meta-data" prefix stripped,
// e.g. "", "instance-id", "network/interfaces/macs/".
func serveTree(w http.ResponseWriter, metaPath string, tree *treeNode) {
	node, ok := tree.lookup(metaPath)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	if node.value != nil {
		fmt.Fprint(w, *node.value) //nolint:errcheck
		return
	}
	fmt.Fprint(w, node.listing()) //nolint:errcheck
}
