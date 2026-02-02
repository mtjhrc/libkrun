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

## Troubleshooting

### `xzcat: command not found`
Install xz: `brew install xz`

### `invalid linker name in argument '-fuse-ld=lld'`
Install lld: `brew install lld`

### Sysroot issues
Clean and rebuild: `rm -rf linux-sysroot && make`
