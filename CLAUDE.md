# CLAUDE.md

This file provides context for AI assistants working on this codebase.

## What this project is

`pve-imds` is an AWS IMDS-compatible metadata service for Proxmox VE. It intercepts TCP connections from guest VMs to `169.254.169.254:80` using AF_XDP + eBPF, adds VM identity headers, and proxies requests to an unprivileged metadata backend over a Unix socket. See [ARCHITECTURE.md](ARCHITECTURE.md) for full design details.

## Repository layout

```
cmd/pve-imds/           # main daemon
cmd/pve-imds-meta/      # metadata backend (planned)
cmd/netlink-recorder/   # dev utility: capture RTNLGRP_LINK messages to file
internal/config/        # Config struct + Viper unmarshaling
internal/logging/       # slog initialisation helper
internal/tapwatch/      # tap interface lifecycle watcher (Watcher, EventSink, Scan, Run)
```

## Architectural patterns

- **CLI**: `cobra` + `viper`.
- **DI**: `uber/fx`
- **Config**: Viper with struct unmarshaling. Config structs in `internal/config/`. Env prefix `PVE_IMDS_`. Layered: config file < env < flags.
- **Logging**: `slog` via a shared `internal/logging` package. Structured fields everywhere.
- **Testability via injectable function fields**: When a struct depends on an OS call (e.g. `net.Interfaces`, `os.ReadFile`), store it as an unexported `func` field and default it to the real implementation in the constructor. Tests in the same package override the field directly — no interface wrapping needed. Example: `Watcher.lister func() ([]net.Interface, error)` defaults to `net.Interfaces`.
- **Startup scan + live watch**: `tapwatch.Watcher.Scan` must be called before `Watcher.Run`. `Scan` enumerates already-up tap interfaces and populates `seen`; `Run` then processes the live netlink stream without re-emitting events for interfaces `Scan` already reported. Wire this in `fx.Hook.OnStart`: call `Scan` synchronously (return any error to abort startup), then launch `Run` in a goroutine.

## Key dependencies

| Package | Purpose |
|---------|---------|
| `github.com/cilium/ebpf` | Load and attach eBPF programs, manage BPF maps |
| `gvisor.dev/gvisor/pkg/tcpip` | Userspace TCP/IP stack for AF_XDP socket |
| `github.com/mdlayher/netlink` | Netlink for tap interface lifecycle events |
| `github.com/spf13/cobra` | CLI subcommands |
| `github.com/spf13/viper` | Configuration |
| `go.uber.org/fx` | Dependency injection |
| `github.com/prometheus/client_golang` | Metrics |

## eBPF development

eBPF C source lives in `internal/xdp/`. Go bindings are generated with `bpf2go`:

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 xdp_redirect xdp_redirect.c
```

Regenerate bindings after changing `.c` files. Committed `.o` and generated `.go` files should be kept in sync. Building the eBPF source requires `clang` and Linux kernel headers; the Go build does not (it uses the pre-compiled `.o`).

The XDP program must:
- Only redirect `dst=169.254.169.254, dport=80, proto=TCP` IPv4 packets
- Use `bpf_redirect_map` with the `XSKMAP`
- Return `XDP_PASS` for all other packets

## VM identity resolution

Interface name `tap{vmid}i{netindex}` → parse vmid and net_index directly.

Full tuple `(node, vmid, qemu_pid, qemu_pid_starttime, net_index, config_digest)`:

- `node`: hostname
- `qemu_pid`: find process with argv matching `kvm.*-id {vmid}` or check `/var/run/qemu-server/{vmid}.pid`
- `qemu_pid_starttime`: field 22 of `/proc/{pid}/stat` (jiffies since boot) — used for PID reuse detection
- `config_digest`: SHA of `/etc/pve/qemu-server/{vmid}.conf`

Cache entries are keyed by tap interface name and invalidated on inotify events for the conf file or on DELLINK.

## Testing expectations

Follow the testing pyramid (see ARCHITECTURE.md). Write unit tests in `_test.go` files alongside the package. Integration tests that require a Linux kernel with BPF support go in `internal/*/integration_test.go` with a build tag `//go:build integration`. E2E/smoke tests are out of scope for this repo for now.

Define interfaces for:
- Identity resolver (`internal/vmid`)
- XDP manager (`internal/xdp`)
- Metadata backend client (`internal/proxy`)

This allows unit tests to use fakes without kernel or Proxmox dependencies.

## Privilege model

The main daemon needs `CAP_NET_ADMIN` + `CAP_BPF` (or root) for XDP attachment. The metadata backend should run unprivileged and communicate only via a Unix socket. Do not conflate the two in a single process.

## What to avoid

- Do not use `flag` package — use cobra/viper.
- Do not use `log` package — use `slog`.
- Do not modify individual Proxmox VM configs or rely on PVE hook scripts.
- Do not forward `X-PVE-*` headers back to the guest.
- Do not use zero-copy XDP mode by default; it requires driver support that may not be universally available.
