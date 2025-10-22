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
    cd examples && PKG_CONFIG_PATH=../examples-prefix/lib64/pkgconfig cargo build

# Build examples in release mode
build-examples-release:
    cd examples && PKG_CONFIG_PATH=../examples-prefix/lib64/pkgconfig cargo build --release

# Install debug build to examples-prefix
install-debug: build-debug
    #!/usr/bin/env bash
    set -e
    mkdir -p examples-prefix/lib64/pkgconfig examples-prefix/include
    # Only copy .so if it's newer or doesn't exist
    if [ ! -f examples-prefix/lib64/libkrun.so.1.15.1 ] || [ target/debug/libkrun.so -nt examples-prefix/lib64/libkrun.so.1.15.1 ]; then
        cp target/debug/libkrun.so examples-prefix/lib64/libkrun.so.1.15.1
    fi
    cd examples-prefix/lib64 && ln -sf libkrun.so.1.15.1 libkrun.so.1 && ln -sf libkrun.so.1 libkrun.so
    cd ../..
    cp -u include/*.h examples-prefix/include/
    # Only regenerate .pc file if it doesn't exist or content changed
    PC_NEW=$(sed -e 's|@prefix@|{{justfile_directory()}}/examples-prefix|' \
        -e 's|@libdir@|{{justfile_directory()}}/examples-prefix/lib64|' \
        -e 's|@includedir@|{{justfile_directory()}}/examples-prefix/include|' \
        -e 's|@PACKAGE_NAME@|libkrun|' \
        -e 's|@PACKAGE_VERSION@|1.15.1|' \
        libkrun.pc.in)
    if [ ! -f examples-prefix/lib64/pkgconfig/libkrun.pc ] || ! echo "$PC_NEW" | cmp -s - examples-prefix/lib64/pkgconfig/libkrun.pc; then
        echo "$PC_NEW" > examples-prefix/lib64/pkgconfig/libkrun.pc
    fi

# Install debug build with input support to examples-prefix
install-debug-input: build-debug-input
    #!/usr/bin/env bash
    set -e
    mkdir -p examples-prefix/lib64/pkgconfig examples-prefix/include
    # Only copy .so if it's newer or doesn't exist
    if [ ! -f examples-prefix/lib64/libkrun.so.1.15.1 ] || [ target/debug/libkrun.so -nt examples-prefix/lib64/libkrun.so.1.15.1 ]; then
        cp target/debug/libkrun.so examples-prefix/lib64/libkrun.so.1.15.1
    fi
    cd examples-prefix/lib64 && ln -sf libkrun.so.1.15.1 libkrun.so.1 && ln -sf libkrun.so.1 libkrun.so
    cd ../..
    cp -u include/*.h examples-prefix/include/
    # Only regenerate .pc file if it doesn't exist or content changed
    PC_NEW=$(sed -e 's|@prefix@|{{justfile_directory()}}/examples-prefix|' \
        -e 's|@libdir@|{{justfile_directory()}}/examples-prefix/lib64|' \
        -e 's|@includedir@|{{justfile_directory()}}/examples-prefix/include|' \
        -e 's|@PACKAGE_NAME@|libkrun|' \
        -e 's|@PACKAGE_VERSION@|1.15.1|' \
        libkrun.pc.in)
    if [ ! -f examples-prefix/lib64/pkgconfig/libkrun.pc ] || ! echo "$PC_NEW" | cmp -s - examples-prefix/lib64/pkgconfig/libkrun.pc; then
        echo "$PC_NEW" > examples-prefix/lib64/pkgconfig/libkrun.pc
    fi

# Install release build to examples-prefix (uses make)
install-release:
    GPU=1 NET=1 make
    PREFIX=examples-prefix make install

# Run gui_vm with custom command (set ROOTFS env var to override default rootfs path)
gui-vm *args: install-debug-input build-examples
    #!/usr/bin/env bash
    set -exo pipefail
    ulimit -n
    cd examples
    ROOTFS=${ROOTFS:-~/c/my_rootfs3_touch}
    
    # Create FIFO for libkrun logs if it doesn't exist
    [[ -p /tmp/mylog ]] || mkfifo /tmp/mylog
    
    RUST_LOG=${RUST_LOG:-devices::virtio::gpu=trace,gtk_display=debug,rutabaga_gfx=debug} \
    LD_LIBRARY_PATH=../examples-prefix/lib64:${LD_LIBRARY_PATH:-} \
    buildah unshare target/debug/gui_vm --root-dir "${ROOTFS}" --display=1920x1080+touch --keyboard-input --color-log /tmp/mylog -- {{args}}

# Run gui_vm with Weston in tmux (seatd + weston in split panes)
gui-vm-weston: install-debug-input build-examples
    #!/usr/bin/env bash
    set -exo pipefail
    ulimit -n
    cd examples
    ROOTFS=${ROOTFS:-~/c/my_rootfs3_touch}
    
    # Create FIFO for libkrun logs if it doesn't exist
    [[ -p /tmp/mylog ]] || mkfifo /tmp/mylog
    
    # Create the weston startup script in the rootfs
    cat > "${ROOTFS}/tmp/start-weston.sh" <<'SCRIPT'
    #!/bin/sh
    set -x
    # Kill any existing tmux session
    tmux kill-session -t weston 2>/dev/null || true
    
    tmux new-session -d -s weston 'sudo /usr/lib/systemd/systemd-udevd --daemon && sudo seatd -u m' || exit 1
    sleep 0.5
    # --use-pixman
    tmux new-window -t weston:1 -n weston 'WAYLAND_DEBUG=0 XDG_RUNTIME_DIR=/tmp/runtime-1000/ weston --backend=drm-backend.so --seat=seat0 --socket=wayland-0' || exit 2
    sleep 2
    # Wait for Wayland socket to be available
    for i in 1 2 3 4 5; do
        [ -S /tmp/runtime-1000/wayland-0 ] && break
        sleep 1
    done
    tmux new-window -t weston:2 -n egl 'XDG_RUNTIME_DIR=/tmp/runtime-1000/ WAYLAND_DISPLAY=wayland-0 weston-simple-egl' || exit 3
    sleep 0.5
    tmux list-windows -t weston
    tmux select-window -t weston:2
    tmux attach -t weston
    SCRIPT
    chmod +x "${ROOTFS}/tmp/start-weston.sh"
    
    RUST_LOG=${RUST_LOG:-devices::virtio::gpu=trace,gtk_display=debug,rutabaga_gfx=debug} \
    LD_LIBRARY_PATH=../examples-prefix/lib64:${LD_LIBRARY_PATH:-} \
    buildah unshare target/debug/gui_vm --root-dir "${ROOTFS}" --display=1920x1080+touch --keyboard-input --color-log /tmp/mylog -- \
        /tmp/start-weston.sh
