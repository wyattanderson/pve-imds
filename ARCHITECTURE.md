# Architecture

## Overview

`pve-imds` intercepts HTTP requests from guest VMs to `169.254.169.254` and proxies them to an unprivileged metadata backend, adding VM identity information as request headers. Privilege separation keeps the high-privilege XDP layer minimal and allows the metadata backend to be replaced or extended independently.

```
┌─────────────────────────────────────────────────────────────┐
│ Proxmox Host                                                │
│                                                             │
│  ┌────────────┐   tap100i0   ┌───────────────────────────┐  │
│  │  VM 100    │◄────────────►│  pve-imds (root/CAP_BPF)  │  │
│  │            │              │                           │  │
│  │  GET /meta │              │  XDP: intercept 169.254.. │  │
│  │  →169.254  │              │  gvisor netstack: HTTP    │  │
│  └────────────┘              │  add identity headers     │  │
│                              │         │                 │  │
│                              └─────────┼─────────────────┘  │
│                                        │ Unix socket        │
│                              ┌─────────▼─────────────────┐  │
│                              │  pve-imds-meta (unpriv.)  │  │
│                              │                           │  │
│                              │  serve metadata           │  │
│                              │  sign identity documents  │  │
│                              └───────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Packet path

1. Guest sends `GET http://169.254.169.254/...` → tap interface on host.
2. eBPF XDP program attached to the tap interface checks: IPv4, TCP, dst=`169.254.169.254`, dport=80. Matching packets are redirected to an AF_XDP socket via `XSKMAP`; non-matching packets pass through normally.
3. gvisor's userspace netstack receives frames from the AF_XDP socket and presents a standard `net.Listener` interface.
4. An HTTP reverse proxy layer adds `X-PVE-*` identity headers and forwards the request to the metadata backend over a Unix socket.
5. The response is returned through the same path.

The XDP program runs in copy-mode (not zero-copy) for compatibility; zero-copy can be enabled where the driver supports it.

## ARP and MAC address handling

Guest VMs reach `169.254.169.254` via one of two paths, each with different ethernet framing:

**Direct ARP path**: The VM ARPs for `169.254.169.254` on the link. The gvisor netstack replies with the tap interface's hardware MAC address. Subsequent data frames arrive with `dst=tap_MAC`.

**Default-gateway path**: The VM's routing table sends packets for non-local destinations through a default gateway. The ethernet frame then carries `dst=gateway_MAC`, not the tap interface's MAC. This is the common case when the guest has not manually configured a route for the link-local range.

In both cases, the VM accepts reply frames only if their ethernet source address matches what the VM placed in the destination — `tap_MAC` for the ARP path, `gateway_MAC` for the gateway path.

`internal/iface.Endpoint` (a `nested.LinkEndpoint` wrapper) handles this uniformly:

- **Inbound**: `DeliverNetworkPacket` extracts the ethernet destination MAC from each arriving IPv4 frame and stores it atomically as `preferredSrcMAC`. Multicast and broadcast addresses (e.g. the `FF:FF:FF:FF:FF:FF` destination of ARP requests) are ignored.
- **Outbound**: `AddHeader` overwrites `pkt.EgressRoute.LocalLinkAddress` with `preferredSrcMAC` before delegating to the child endpoint to encode the ethernet frame. If no unicast inbound frame has been seen yet (e.g. the very first outbound frame is an ARP reply), the field is left unchanged and gvisor uses the tap interface's own MAC, which is correct for ARP replies.

The first unicast data frame from the VM — whether sourced via ARP or a gateway — establishes `preferredSrcMAC` for the lifetime of that interface's runtime.

## Interface lifecycle

At daemon startup, `tapwatch.Watcher.Scan` enumerates existing network interfaces and emits `Created` events for any tap interface that is already up. `Watcher.Run` then takes over and processes the live `RTNLGRP_LINK` netlink stream. Both share the same `seen` map, so `Run` will not re-emit `Created` for interfaces already reported by `Scan`.

```
daemon start
    │
    ▼
tapwatch.Scan  ──►  net.Interfaces()  ──►  Created event per up tap{vmid}i{n}
    │
    ▼
tapwatch.Run (goroutine)
    │
    ├── netlink RTM_NEWLINK (tap prefix, UP)
    │       │
    │       ▼
    │   Created event
    │
    └── netlink RTM_DELLINK
            │
            ▼
        Deleted event

Created event  ──►  parse vmid + net_index from interface name
                        │
                        ▼
                    lookup VM identity (cache → /etc/pve/qemu-server/)
                        │
                        ▼
                    create AF_XDP socket
                    load & attach eBPF program
                    register HTTP proxy handler

Deleted event  ──►  detach XDP, close socket, remove handler
```

Interface names follow the Proxmox convention `tap{vmid}i{netindex}`. The daemon may also watch `/etc/pve/qemu-server/*.conf` via inotify to detect config changes (e.g., config digest updates) without relying on netlink alone, since Proxmox does not guarantee a generic pre/post-start hook mechanism.

## VM identity cache

Resolving the identity tuple `(node, vmid, net_index, config_digest)` involves filesystem reads. This information is cached in memory per tap interface and refreshed:

- On interface creation (cold start).
- When a request arrives and the config digest has changed (detected lazily from `inotify` or on-demand hash comparison).
- Explicitly on cache invalidation signals.

VM restarts are handled by the tap interface lifecycle: Proxmox tears down the tap on VM stop (DELLINK evicts the entry) and recreates it on start (NEWLINK populates a fresh entry).

## Repository layout

```
pve-imds/
├── cmd/
│   ├── pve-imds/               # Main daemon binary
│   │   └── main.go
│   ├── pve-imds-meta/          # Metadata backend binary (planned)
│   └── netlink-recorder/       # Dev utility: capture RTNLGRP_LINK messages to file
│       └── main.go
├── internal/
│   ├── config/                 # Config struct + Viper unmarshaling
│   ├── iface/                  # Per-interface gvisor stack + HTTP server
│   │   ├── iface.go            # Runtime: AF_XDP socket, stack wiring, HTTP handler
│   │   ├── stack.go            # newIMDSStack, serveIMDS
│   │   ├── staticarp.go        # Endpoint: static neighbor learning + MAC rewriting
│   │   └── *_test.go
│   ├── identity/               # VM identity resolution and caching
│   ├── logging/                # slog initialisation helper
│   ├── manager/                # Interface lifecycle manager
│   ├── tapwatch/               # Tap interface lifecycle watcher (netlink)
│   ├── vmconfig/               # Proxmox VM config parsing
│   └── xdp/                    # eBPF program + bpf2go bindings
├── go.mod
├── go.sum
├── README.md
├── ARCHITECTURE.md
└── CLAUDE.md
```

## CLI and configuration

Binaries use [spf13/cobra](https://github.com/spf13/cobra) for subcommand structure and [spf13/viper](https://github.com/spf13/viper) for configuration. [uber/fx](https://github.com/uber-go/fx) wires components together via dependency injection.

Typical invocation:

```sh
pve-imds --socket /run/pve-imds-meta.sock --log-level info
```

Configuration is layered: config file < environment variables (`PVE_IMDS_*`) < CLI flags.

## Observability

- **Logging**: structured `slog` throughout, with tap interface name and VMID as common log fields.
- **Metrics**: Prometheus metrics exposed on a configurable HTTP port. Key metrics include:
  - Active tap interfaces under management
  - Requests proxied / errors by interface
  - XDP redirect counts (from eBPF map statistics)
  - Identity cache hit/miss ratio
  - Backend unix socket latency histogram

## Testing strategy

The project targets a testing pyramid:

| Layer | Approach |
|-------|----------|
| **Unit** | Pure Go logic: interface name parsing, identity cache, header injection, config parsing. No kernel or Proxmox required. |
| **Integration** | XDP socket attachment and packet forwarding tested with a `veth` pair and a minimal network namespace. Requires Linux with BPF support; suitable for CI on a capable kernel. |
| **Smoke / E2E** | Full stack test against a real Proxmox host. Validates end-to-end: VM boots, queries IMDS, receives correct metadata. Run manually or in a dedicated environment. |

Packages are designed for testability: interfaces are defined for the identity resolver, XDP manager, and backend client so they can be replaced with fakes in unit tests.

## Security considerations

- The main daemon runs with `CAP_NET_ADMIN` and `CAP_BPF` (or root) for XDP attachment. It should drop unnecessary capabilities after startup.
- The metadata backend runs as an unprivileged user and is only reachable via Unix socket with appropriate ownership/permissions.
- VM identity headers (`X-PVE-*`) must not be forwarded back to the guest.
- The eBPF program only redirects the exact `169.254.169.254:80` target; all other traffic passes through unmodified.
