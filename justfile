# libkrun development commands

# Default recipe - show available commands
default:
    @just --list

# Build libkrun in debug mode
build-debug:
    cargo build --features net,gpu

# Build libkrun in debug mode with input support
build-debug-input:
    cargo build --features net,gpu,input

# Build libkrun in release mode
build-release:
    cargo build --release --features net,gpu

# Build examples in debug mode
build-examples:
    cd examples && PKG_CONFIG_PATH=../examples-prefix/lib64/pkgconfig cargo build --bins

# Build examples in release mode
build-examples-release:
    cd examples && PKG_CONFIG_PATH=../examples-prefix/lib64/pkgconfig cargo build --bins --release

# Install debug build to examples-prefix
install-debug: build-debug
    mkdir -p examples-prefix/lib64/pkgconfig examples-prefix/include
    cp target/debug/libkrun.so examples-prefix/lib64/libkrun.so.1.15.1
    cd examples-prefix/lib64 && ln -sf libkrun.so.1.15.1 libkrun.so.1 && ln -sf libkrun.so.1 libkrun.so
    cp include/*.h examples-prefix/include/
    sed -e 's|@prefix@|{{justfile_directory()}}/examples-prefix|' \
        -e 's|@libdir@|{{justfile_directory()}}/examples-prefix/lib64|' \
        -e 's|@includedir@|{{justfile_directory()}}/examples-prefix/include|' \
        -e 's|@PACKAGE_NAME@|libkrun|' \
        -e 's|@PACKAGE_VERSION@|1.15.1|' \
        libkrun.pc.in > examples-prefix/lib64/pkgconfig/libkrun.pc

# Install debug build with input support to examples-prefix
install-debug-input: build-debug-input
    mkdir -p examples-prefix/lib64/pkgconfig examples-prefix/include
    cp target/debug/libkrun.so examples-prefix/lib64/libkrun.so.1.15.1
    cd examples-prefix/lib64 && ln -sf libkrun.so.1.15.1 libkrun.so.1 && ln -sf libkrun.so.1 libkrun.so
    cp include/*.h examples-prefix/include/
    sed -e 's|@prefix@|{{justfile_directory()}}/examples-prefix|' \
        -e 's|@libdir@|{{justfile_directory()}}/examples-prefix/lib64|' \
        -e 's|@includedir@|{{justfile_directory()}}/examples-prefix/include|' \
        -e 's|@PACKAGE_NAME@|libkrun|' \
        -e 's|@PACKAGE_VERSION@|1.15.1|' \
        libkrun.pc.in > examples-prefix/lib64/pkgconfig/libkrun.pc

# Install release build to examples-prefix (uses make)
install-release:
    GPU=1 NET=1 make
    PREFIX=examples-prefix make install

# Run gui_vm with debug build and tracing
run rootfs="~/c/my_rootfs3" display="1920x1080+touch": install-debug build-examples
    #!/usr/bin/env bash
    set -euxo pipefail
    cd examples
    RUST_LOG=devices::virtio::gpu=trace,gtk_display=debug \
    LD_LIBRARY_PATH=../examples-prefix/lib64:${LD_LIBRARY_PATH:-} \
    buildah unshare target/debug/gui_vm --root-dir {{rootfs}} --display={{display}} -- /bin/bash

# Run gui_vm with release build
run-release rootfs="~/c/my_rootfs3" display="1920x1080+touch": install-release build-examples-release
    #!/usr/bin/env bash
    set -euxo pipefail
    cd examples
    LD_LIBRARY_PATH=../examples-prefix/lib64:${LD_LIBRARY_PATH:-} \
    buildah unshare target/release/gui_vm --root-dir {{rootfs}} --display={{display}} -- /bin/bash

# Complete debug workflow - build, install, and run
dev rootfs="~/c/my_rootfs3" display="1920x1080+touch": install-debug build-examples
    #!/usr/bin/env bash
    set -euxo pipefail
    cd examples
    RUST_LOG=devices::virtio::gpu=trace,gtk_display=debug \
    LD_LIBRARY_PATH=../examples-prefix/lib64:${LD_LIBRARY_PATH:-} \
    buildah unshare target/debug/gui_vm --root-dir {{rootfs}} --display={{display}} -- /bin/bash

# Quick gui_vm with single display (debug build)
gui-vm rootfs="~/c/my_rootfs3" command="/bin/bash": install-debug-input build-examples
    #!/usr/bin/env bash
    set -euxo pipefail
    cd examples
    RUST_LOG=devices::virtio::gpu=trace,gtk_display=debug \
    LD_LIBRARY_PATH=../examples-prefix/lib64:${LD_LIBRARY_PATH:-} \
    buildah unshare target/debug/gui_vm --root-dir {{rootfs}} --display=1920x1080 -- {{command}}

# Run gui_vm with custom command (uses default rootfs)
gui-vm-run command: install-debug-input build-examples
    #!/usr/bin/env bash
    set -euxo pipefail
    cd examples
    RUST_LOG=${RUST_LOG:-devices::virtio::gpu=trace,gtk_display=debug,rutabaga_gfx=debug} \
    GSK_RENDERER=gl \
    LD_LIBRARY_PATH=../examples-prefix/lib64:${LD_LIBRARY_PATH:-} \
    buildah unshare target/debug/gui_vm --root-dir ~/c/my_rootfs3 --display=1920x1080 -- {{command}}

# Run clippy on libkrun
clippy:
    cargo clippy --release --features gpu

# Run cargo fmt on libkrun
fmt:
    cargo fmt --all

# Clean build artifacts
clean:
    cargo clean
    cd examples && cargo clean
    rm -rf examples-prefix

# Run tests
test:
    make test

