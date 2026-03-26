/*
 * v2 API example: chroot-like functionality with libkrun.
 *
 * Usage: chroot_vm_v2 NEWROOT COMMAND [ARGS...]
 *
 * Executes COMMAND inside a lightweight VM with NEWROOT as the rootfs,
 * using the new typed builder API.
 *
 * Build:
 *   cc -o chroot_vm_v2 chroot_vm_v2.c -lkrun
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libkrun.h>

int main(int argc, char *const argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s NEWROOT COMMAND [ARGS...]\n", argv[0]);
        return 1;
    }

    const char *new_root = argv[1];
    const char *guest_cmd = argv[2];

    /* Initialize logging at warn level */
    KrunErrorCode err = krun_krunlog_init(2);
    if (err.code) {
        fprintf(stderr, "log init failed: %s\n", krun_error_code_message(&err));
        krun_error_code_free(&err);
        return 1;
    }

    /* Create rootfs virtiofs device */
    KrunFsDevice rootfs;
    err = krun_fsdevice_new(KRUN_STR("rootfs"), KRUN_STR(new_root), &rootfs);
    if (err.code) {
        fprintf(stderr, "fs device failed: %s\n", krun_error_code_message(&err));
        krun_error_code_free(&err);
        return 1;
    }

    /* Create payload */
    KrunLibkrunInitBuilder payload_builder = krun_libkruninit_builder(rootfs);

    KrunStr guest_args[argc - 3];
    for (int i = 3; i < argc; i++) {
        guest_args[i - 3] = KRUN_STR(argv[i]);
    }
    err = krun_libkruninitbuilder_set_exec(payload_builder,
        KRUN_STR(guest_cmd), guest_args, argc - 3);
    if (err.code) {
        fprintf(stderr, "set exec failed: %s\n", krun_error_code_message(&err));
        krun_error_code_free(&err);
        return 1;
    }

    err = krun_libkruninitbuilder_set_workdir(payload_builder, KRUN_STR("/"));
    if (err.code) {
        fprintf(stderr, "set workdir failed: %s\n", krun_error_code_message(&err));
        krun_error_code_free(&err);
        return 1;
    }

    KrunStr env[] = { KRUN_STR("HOME=/root"), KRUN_STR("TERM=xterm-256color") };
    err = krun_libkruninitbuilder_set_env(payload_builder, env, 2);
    if (err.code) {
        fprintf(stderr, "set env failed: %s\n", krun_error_code_message(&err));
        krun_error_code_free(&err);
        return 1;
    }

    KrunLibkrunInit payload;
    err = krun_libkruninitbuilder_build(payload_builder, &payload);
    if (err.code) {
        fprintf(stderr, "build payload failed: %s\n", krun_error_code_message(&err));
        krun_error_code_free(&err);
        return 1;
    }

    /* Create console with stdin as TTY port */
    KrunConsoleDeviceBuilder console_builder = krun_consoledevice_builder();
    uint32_t port_idx;
    err = krun_consoledevicebuilder_add_tty_port(console_builder, STDIN_FILENO, &port_idx);
    if (err.code) {
        fprintf(stderr, "add tty port failed: %s\n", krun_error_code_message(&err));
        krun_error_code_free(&err);
        return 1;
    }

    KrunConsoleDevice console;
    err = krun_consoledevicebuilder_build(console_builder, &console);
    if (err.code) {
        fprintf(stderr, "build console failed: %s\n", krun_error_code_message(&err));
        krun_error_code_free(&err);
        return 1;
    }

    /* Create balloon and rng */
    KrunBalloonDevice balloon;
    err = krun_balloondevice_new(&balloon);
    if (err.code) {
        fprintf(stderr, "balloon failed: %s\n", krun_error_code_message(&err));
        krun_error_code_free(&err);
        return 1;
    }

    KrunRngDevice rng;
    err = krun_rngdevice_new(&rng);
    if (err.code) {
        fprintf(stderr, "rng failed: %s\n", krun_error_code_message(&err));
        krun_error_code_free(&err);
        return 1;
    }

    /* Build the VM */
    KrunVmmBuilder builder = krun_vmmbuilder_new();

    err = krun_vmmbuilder_set_vcpus(builder, 2);
    if (err.code) { fprintf(stderr, "set vcpus: %s\n", krun_error_code_message(&err)); return 1; }

    err = krun_vmmbuilder_set_ram_mib(builder, 512);
    if (err.code) { fprintf(stderr, "set ram: %s\n", krun_error_code_message(&err)); return 1; }

    krun_vmmbuilder_set_payload(builder, payload);
    krun_vmmbuilder_add_fs_device(builder, rootfs);
    krun_vmmbuilder_add_console_device(builder, console);
    krun_vmmbuilder_set_balloon(builder, balloon);
    krun_vmmbuilder_set_rng(builder, rng);

    KrunKrunVmm vmm;
    err = krun_vmmbuilder_build(builder, &vmm);
    if (err.code) {
        fprintf(stderr, "build vmm failed: %s\n", krun_error_code_message(&err));
        krun_error_code_free(&err);
        return 1;
    }

    /* Run the VM (blocks until guest exits) */
    krun_krunvmm_run(vmm);

    krun_krunvmm_destroy(vmm);
    return 0;
}
