# Building libkrun on macOS

## Prerequisites

Building the non-EFI variant of libkrun on macOS requires cross-compiling a Linux `init` binary. This needs:

### Required Tools

```bash
# Install LLVM linker (lld) and xz for decompressing Debian packages
brew install lld xz
```

### What the build does automatically

1. Downloads Debian package index for the target architecture (arm64/bookworm)
2. Downloads and extracts required packages to create a Linux sysroot:
   - `libc6` - glibc runtime
   - `libc6-dev` - glibc development headers
   - `libgcc-12-dev` - GCC support library
   - `linux-libc-dev` - Linux kernel headers
3. Cross-compiles `init/init` using clang with lld linker
4. Builds the Rust library with cargo

## Building

```bash
# Standard build (downloads sysroot automatically)
make

# With network support
make NET=1

# Clean build (removes sysroot too)
make clean-all
```

## Git Remote Setup

To push code from a Linux machine to the Mac for building:

```bash
# On the Mac: Create repo that allows receiving pushes
mkdir -p ~/Dev/libkrun-vectored-io
cd ~/Dev/libkrun-vectored-io
git init
git config receive.denyCurrentBranch updateInstead

# On Linux: Add Mac as remote and push
git remote add mtj-rh-mac mhrica@mtj-rh-mac.local:~/Dev/libkrun-vectored-io
git push mtj-rh-mac HEAD:main --force
```

## SSH Notes

When running commands via SSH, brew and other tools may not be in PATH because the shell profile isn't loaded. Use a login shell:

```bash
ssh user@mac "zsh -l -c 'make'"
```

**Security**: The workflow is one-way - Linux can SSH into the Mac, but the Mac should NOT have SSH access back to Linux. Do not add Linux as a git remote on the Mac.

## Running Tests with gvproxy

gvproxy (from Podman) provides userspace networking for VMs using the vfkit protocol over unixgram sockets.

### gvproxy Location

```bash
# Typical location (version may vary)
/opt/homebrew/Cellar/podman/5.5.1/libexec/podman/gvproxy

# Or find it via Podman
/opt/homebrew/opt/podman/libexec/podman/gvproxy
```

### Manual Testing

```bash
# Start gvproxy with vfkit unixgram backend
/opt/homebrew/Cellar/podman/5.5.1/libexec/podman/gvproxy --listen-vfkit unixgram:/tmp/mynet

# This creates a unixgram socket at /tmp/mynet
# libkrun connects via krun_add_net_unixgram() with NET_FLAG_VFKIT

# Network configuration:
# - Gateway: 192.168.127.1
# - Guest IP: 192.168.127.2
# - Netmask: 255.255.255.0
```

### Running the gvproxy test

```bash
# Build with NET support
make NET=1

# Run the gvproxy test
make test NET=1 TEST=net-gvproxy TEST_FLAGS="--base-dir ./test-output --keep-all"
```

## Troubleshooting

### `xzcat: command not found`
Install xz: `brew install xz`

### `invalid linker name in argument '-fuse-ld=lld'`
Install lld: `brew install lld`

### Sysroot issues
Clean and rebuild: `rm -rf linux-sysroot && make`
