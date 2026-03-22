# pve-imds

An AWS IMDS-compatible metadata service for Proxmox VE virtual machines.

Virtual machines running on a Proxmox host can reach `http://169.254.169.254` to retrieve instance metadata and a signed instance identity document — the same endpoint pattern used by AWS EC2, allowing unmodified cloud-init configurations and tooling to work transparently.

## How it works

Proxmox attaches each VM's virtual NIC to a Linux tap interface (e.g., `tap100i0`). `pve-imds` watches for these interfaces via netlink, attaches an AF_XDP socket with an eBPF XDP program that intercepts TCP traffic destined for `169.254.169.254:80`, and presents a userspace HTTP server (via gvisor's netstack) on that address. Intercepted requests are enriched with VM-identifying headers and forwarded to a separate metadata backend over a Unix socket.

No changes to individual VM configurations are required.

## Components

| Binary | Description |
|--------|-------------|
| `pve-imds` | Main daemon. Watches for tap interfaces, manages XDP attachment, proxies requests to the metadata backend. Runs as a systemd service. |
| `pve-imds-meta` _(planned)_ | Unprivileged metadata backend. Serves metadata and signed identity documents over a Unix socket. |

## VM identification

From the tap interface name, `pve-imds` derives a tuple forwarded as HTTP headers to the backend:

| Header | Source |
|--------|--------|
| `X-PVE-Node` | hostname |
| `X-PVE-VMID` | parsed from interface name (`tap{vmid}i{index}`) |
| `X-PVE-Net-Index` | parsed from interface name |
| `X-PVE-Config-Digest` | from `/etc/pve/qemu-server/{vmid}.conf` — detects config changes |

## Requirements

- Proxmox VE host (Linux 5.9+ for AF_XDP support)
- Root or `CAP_NET_ADMIN` / `CAP_BPF` capabilities
- Go 1.24+ with CGO enabled
- `clang` and Linux kernel headers for eBPF compilation

## Development

```sh
# Build all binaries
go build ./cmd/...

# Run tests
go test ./...

# Regenerate eBPF Go bindings (requires clang + bpf2go)
go generate ./internal/xdp/...
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for design details.
