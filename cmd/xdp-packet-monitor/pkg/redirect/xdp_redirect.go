package redirect

import (
	"net"

	"github.com/cilium/ebpf/link"
	"gvisor.dev/gvisor/pkg/cleanup"
)

func LoadAndAttach(sockfd int, iface *net.Interface) (func(), error) {
	var objs xdp_redirectObjects
	if err := loadXdp_redirectObjects(&objs, nil); err != nil {
		return nil, err
	}
	cl := cleanup.Make(func() { objs.Close() })
	defer cl.Clean()

	attached, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRedirectProg,
		Interface: iface.Index,
	})
	if err != nil {
		return nil, err
	}
	cl.Add(func() { attached.Close() })

	key := uint32(0)
	val := uint32(sockfd)
	err = objs.XsksMap.Update(&key, &val, 0 /* flags */)
	if err != nil {
		return nil, err
	}

	return cl.Release(), nil
}
