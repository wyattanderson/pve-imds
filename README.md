# pve-imds

An OpenStack and EC2 IMDS (Instance Metadata Service) compatible metadata service for virtual machines running in Proxmox.

With `pve-imds`, an unmodified Linux [cloud image](https://cloud-images.ubuntu.com/) running [cloud-init](https://docs.cloud-init.io/en/latest/explanation/introduction.html) can reach `http://169.254.169.254` to retrieve not only instance metadata but also **custom [user data](https://docs.cloud-init.io/en/latest/explanation/format/index.html)** stored in the Proxmox VM *Notes* field. Eventually, `pve-imds` will also support a **signed identity document** that a VM can use to authenticate to a service like Vault.

## Quick start

1. Download the [latest release](https://github.com/wyattanderson/pve-imds/releases/latest) of `pve-imds` and install it. This snippet will fetch the latest `.deb` package artifact URL from the GitHub API, download, and install it. It's all here for the sake of transparency over a `curl ... | sudo bash` alternative.

```bash
# Protip: hit the ⧉ button to copy to the clipboard then paste the whole command.
SUDO=$(command -v sudo >/dev/null 2>&1 && echo sudo || echo '') && \
tmp=$(mktemp --suffix=.deb) && \
curl -fL "$(curl -fsSL https://api.github.com/repos/wyattanderson/pve-imds/releases/latest \
    | python3 -c 'import sys,json;print(next(a["browser_download_url"] for a in json.load(sys.stdin)["assets"] if a["name"].endswith(".deb")))')" -o "$tmp" && \
$SUDO dpkg -i "$tmp" && \
rm -f "$tmp"
```

2. Download the latest cloud image from your distribution of choice. Here, we'll use Ubuntu 24.04 LTS:

```bash
curl -LO https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
```

3. Import the cloud image as a new VM template. Substitute `local-lvm` and `vmbr0` with your storage and bridge interface of choice. The `--smbios1` configuration is necessary in order to convince `cloud-init` to look out over the network for configuration instead of expecting a CDROM.

```bash
qm create $(pvesh get /cluster/nextid) \
    --name noble-server-cloudimg-amd64 \
    --agent enabled=1 \
    --cpu cputype=host \
    --memory 2048 \
    --scsi0 local-lvm:0,import-from=$(pwd)/noble-server-cloudimg-amd64.img \
    --scsihw virtio-scsi-single \
    --smbios1 base64=1,product=$(echo -n 'OpenStack Nova' | base64) \
    --template 1 \
    --storage local-lvm \
    --net0 bridge=vmbr0,model=virtio
```

4. Note the VM ID of your new template. Set some user data and clone your template into a new VM:

```bash
cat << EOF > user-data
#cloud-config
package_update: true
packages:
  - qemu-guest-agent
ssh_authorized_keys:
  # replace this with your own SSH public key
  - ssh-ed25519 AAAAC3NzaC1lZ...
EOF

# pve-imds reads user data from the contents 
qm clone <TEMPLATE VMID> $(pvesh get /cluster/nextid) --description "$(echo '<!--#user-data'; cat user-data; echo '-->')" --name "my-test-vm"
```

5. Boot your new VM and try SSHing in.

## Why not use the cloud-init support built-in to Proxmox?

Custom user data affords an incredibly powerful way to provision machines with `cloud-init`. It is extensively customizable and is an industry-standard method for complete unattended provisioning of machines.

Proxmox has [basic support for cloud-init](https://pve.proxmox.com/wiki/Cloud-Init_Support) that works by generating an ISO image and attaching it to the VM. Unfortunately, Proxmox only lets you configure custom user data if you provide it via a snippet file from a storage source that supports snippets. This adds complexity, especially around replication.

With `pve-imds`, you can embed custom user data in the *Notes* field of a VM (inside a comment tag, so it isn't visible). This field is stored in the VM's replicated configuration file in `/etc/pve/qemu-server/<VMID>.conf`. Additionally, `pve-imds` serves all of the VM's metadata, **including VM tags** which can be fed into a config management tool like Ansible or Salt to specify things like machine roles or environments.

### Instance identity documents and trust

For me, these capabilites alone were valuable enough to develop `pve-imds`. However, I also wanted a pathway to something like the AWS EC2 [instance identity document](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html), which provides an external mechanism for **cryptographically verifying instance metadata**. So, if you're using Proxmox tags to specify that a VM is a `mysql` server in the `prod` environment, that VM can *prove it* to another service that trusts a public key.

## Why network-based configuration?

The ISO image approach that Proxmox uses (and that I used before this by generating my own ISO images with my own user data) isn't dynamic. With this approach, metadata is up-to-date immediately. Change a tag? Add user data? Immediately visible in the instance without regenerating the image.

## How it works

I think the EC2 IMDS approach (now shared by other hypervisors and clouds) is extremely elegant. A VM can make a request to `http://169.254.169.254` and retrieve information about itself, like looking in a mirror. The VM doesn't even need a valid DHCP lease because `169.254.169.254` is a [link-local IP address](https://en.wikipedia.org/wiki/Link-local_address) and the packets (at least in the case of `pve-imds`) never leave the hypervisor.

This does make the solution slightly more complicated. To provide a strong guarantee that a VM will be able to retrieve its identity *and only its identity*, the hypervisor must be able to intercept and directly respond to packets leaving the VM destined for `169.264.169.254`. Doing this at line rate speeds is challenging. In the cloud, hypervisors (I'm guessing) offload this interception to hardware like [AWS Nitro](https://aws.amazon.com/ec2/nitro/). In the case of `pve-imds`, we use XDP ([eXpress Data Path](https://en.wikipedia.org/wiki/Express_Data_Path)) to intercept packets as soon as they hit the VM's `tap` interface before they hit the rest of the kernel networking stack (or whatever, I'm not an expert). I've been able to maintain full line rate from a VM bridged to a 25GbE network with this approach.

XDP intercepts the full Ethernet frame, so we use the [gVisor userspace TCP stack](gvisor.dev/gvisor/pkg/tcpip/stack) to handle the path between the raw `AF_XDP` socket and the VM-specific HTTP handler. An in-memory metadata cache parses Proxmox VM configuration files for updates, refreshing as necessary via [fsnotify](https://github.com/fsnotify/fsnotify).

## Known limitations

My goal with releasing this is to hopefully improve it with community feedback. I find it useful in my homelab. There is absolutely no warranty, express or implied, that it is suitable in its current or future form for any use case of any import. Use at your own risk.

I have only tested this with VMs running on Proxmox 9 using `virtio` interfaces (though I don't think the interface type matters). This *will not work* with VMs using SR-IOV, unless the VM has a secondary interface with a link-local address.

## Future work

- instance identity documents
- hardware offload using [ASAP<sup>2</sup> direct](https://docs.nvidia.com/networking/display/mlnxofedv24103250lts/ovs+offload+using+asap%C2%B2+direct)

## AI disclosure

This was not vibe-coded. I used Claude Code to author most of the code here, but by specifying exactly the architecture and approach that I personally designed as an experienced software and infrastructure engineer, and with thorough review. I could have written all of this on my own (and I did for the prototype), but this approach saved me a fuckton of time and enabled me to do things like write conformance tests that test `pve-imds` against `cloud-init`.