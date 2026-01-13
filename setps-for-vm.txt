## 1) Host prerequisites (Linux host with KVM)

You need hardware virtualization enabled (Intel VT-x / AMD-V) and KVM available.

Install minimal tooling (Debian/Ubuntu host example):

```bash
sudo apt-get update
sudo apt-get install -y \
  qemu-system-x86 qemu-utils cloud-image-utils \
  openssh-client curl
```

That’s enough for: download image, create qcow2 overlays, generate cloud-init ISO, boot QEMU, and SSH in.

---

## 2) Create a working directory

```bash
mkdir -p ebpf-vm/{cloudinit,images,run,artifacts}
cd ebpf-vm
```

---

## 3) Download a small distro image with good deps

Use Ubuntu 24.04 LTS cloud image (small, modern kernel, easy deps):

```bash
curl -L -o images/ubuntu-24.04-server-cloudimg-amd64.img \
  https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
```

If you want extra rigor, also download and verify SHA256 from the same directory.

---

## 4) Cloud-init for a “golden” provisioning boot

### `cloudinit/user-data`
Creates a user, enables SSH key login, and installs common eBPF user-space + build deps.

Replace `ssh-ed25519 AAAA...` with your public key.

```yaml
#cloud-config
users:
  - name: tester
    groups: [sudo]
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    ssh_authorized_keys:
      - ssh-ed25519 AAAA... yourkey

package_update: true
package_upgrade: false

packages:
  # build toolchain
  - build-essential
  - pkg-config
  - clang
  - llvm
  - lld

  # common eBPF user tooling + libs
  - libbpf-dev
  - bpftool
  - libelf-dev
  - zlib1g-dev

  # useful for tc/XDP/cgroup net testing
  - iproute2
  - ethtool

write_files:
  - path: /usr/local/bin/guest-selfcheck.sh
    permissions: "0755"
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      echo "Kernel: $(uname -r)"
      echo -n "BTF vmlinux present: "
      test -e /sys/kernel/btf/vmlinux && echo yes || echo no
      echo "bpftool feature probe (summary):"
      bpftool feature probe | sed -n '1,80p'

runcmd:
  - [bash, -lc, "/usr/local/bin/guest-selfcheck.sh | tee /var/log/guest-selfcheck.log"]
final_message: "cloud-init finished"
```

### `cloudinit/meta-data`

```yaml
instance-id: ebpf-vm
local-hostname: ebpf-vm
```

Generate the seed ISO:

```bash
cloud-localds run/seed.iso cloudinit/user-data cloudinit/meta-data
```

---

## 5) Build a golden image once (packages preinstalled)

Create a writable “golden” qcow2 based on the downloaded image:

```bash
qemu-img create -f qcow2 -b ../images/ubuntu-24.04-server-cloudimg-amd64.img -F qcow2 \
  images/golden.qcow2 20G
```

Boot it one time to let cloud-init install packages:

```bash
qemu-system-x86_64 \
  -enable-kvm -cpu host -smp 4 -m 4096 \
  -drive if=virtio,format=qcow2,file=images/golden.qcow2 \
  -drive if=virtio,format=raw,file=run/seed.iso \
  -netdev user,id=n1,hostfwd=tcp::2222-:22 \
  -device virtio-net-pci,netdev=n1 \
  -nographic
```

When cloud-init finishes, power it off (from another terminal):

```bash
ssh -p 2222 -o StrictHostKeyChecking=no tester@127.0.0.1 'sudo poweroff'
