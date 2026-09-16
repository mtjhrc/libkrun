ARCH = $(shell uname -m)
OS = $(shell uname -s)
PREFIX ?= ../prefix
LIBDIR_Linux = lib64
LIBDIR_Darwin = lib
ifneq ($(PREFIX),)
    PKG_CONFIG_PATH := $(abspath $(PREFIX)/$(LIBDIR_$(OS)))/pkgconfig:$(PKG_CONFIG_PATH)
    RPATH_FLAGS := -Wl,-rpath,$(abspath $(PREFIX)/$(LIBDIR_$(OS)))
endif
PKG_CONFIG_ENV = PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)"
PKG_CONFIG_CFLAGS = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags libkrun libkrun_init)
PKG_CONFIG_LIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs libkrun libkrun_init) $(RPATH_FLAGS)
PKG_CONFIG_LIBRARY_DIRS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs-only-L libkrun) $(RPATH_FLAGS)
LDFLAGS_sev = $(PKG_CONFIG_LIBRARY_DIRS) -lkrun-sev
LDFLAGS_tdx = $(PKG_CONFIG_LIBRARY_DIRS) -lkrun-tdx
LDFLAGS_nitro = $(PKG_CONFIG_LIBRARY_DIRS) -lkrun-awsnitro
CFLAGS = -O2 -g $(PKG_CONFIG_CFLAGS)
ROOTFS_DISTRO := fedora
ROOTFS_DIR = rootfs_$(ROOTFS_DISTRO)

.PHONY: clean rootfs

EXAMPLES := boot_efi chroot_vm external_kernel consoles
ifeq ($(SEV),1)
    EXAMPLES := launch-tee
endif
ifeq ($(TDX),1)
    EXAMPLES := launch-tee
endif

all: $(EXAMPLES)

chroot_vm: chroot_vm.c
	$(CC) -o $@ $< $(CFLAGS) $(PKG_CONFIG_LIBS)
ifeq ($(OS),Darwin)
	codesign --entitlements chroot_vm.entitlements --force -s - $@
endif

launch-tee: launch-tee.c
ifeq ($(SEV),1)
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS_sev)
endif
ifeq ($(TDX),1)
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS_tdx)
endif

boot_efi: boot_efi.c
	$(CC) -o $@ $< $(CFLAGS) $(PKG_CONFIG_LIBS)
ifeq ($(OS),Darwin)
	codesign --entitlements chroot_vm.entitlements --force -s - $@
endif

external_kernel: external_kernel.c
	$(CC) -o $@ $< $(CFLAGS) $(PKG_CONFIG_LIBS)
ifeq ($(OS),Darwin)
	codesign --entitlements chroot_vm.entitlements --force -s - $@
endif

consoles: consoles.c
	$(CC) -o $@ $< $(CFLAGS) $(PKG_CONFIG_LIBS)

nitro: nitro.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS_nitro)

# Build the rootfs to be used with chroot_vm.
rootfs:
	mkdir -p $(ROOTFS_DIR)
	podman create --name libkrun_chroot_vm $(ROOTFS_DISTRO)
	podman export libkrun_chroot_vm | tar xpf - -C $(ROOTFS_DIR)
	podman rm libkrun_chroot_vm

clean:
	rm -rf chroot_vm $(ROOTFS_DIR) launch-tee boot_efi external_kernel nitro consoles
