/*
 * Multiport virtio-console example using the libkrun v2 API.
 *
 * Usage: consoles ROOT_DIR COMMAND [ARGS...]
 *
 * Creates tmux-backed TTY ports and a FIFO inout port, then runs COMMAND
 * in a VM with ROOT_DIR as the rootfs.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libkrun.h>
#include <libkrun_init.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static bool push_to_stderr(void *userdata, KrunStr s)
{
    (void)userdata;
    fwrite(s.data, 1, s.len, stderr);
    return true;
}

static KrunVtableHandle stderr_writer = KRUN_VTABLE_HANDLE(
    KRUN_PUSH_STR_TYPE_TAG,
    ((KrunPushStrVtable){ .drop = NULL, .push = push_to_stderr }),
    NULL);

static KrunVtableHandle stderr_writer_init = KRUN_VTABLE_HANDLE(
    KRUN_INIT_PUSH_STR_TYPE_TAG,
    ((KrunInitPushStrVtable){ .drop = NULL, .push = push_to_stderr }),
    NULL);

#define TRY(call)                                                              \
    err = NULL;                                                                \
    call;                                                                      \
    if (err) {                                                                 \
        flockfile(stderr);                                                     \
        fprintf(stderr, "%s failed: ", #call);                                 \
        krun_error_message(err, &stderr_writer);                               \
        fputc('\n', stderr);                                                   \
        funlockfile(stderr);                                                   \
        krun_error_destroy(err);                                               \
        return 1;                                                              \
    }

static int cmd_output(char *output, size_t output_size, const char *prog, ...)
{
    va_list args;
    const char *argv[32];
    int argc = 0;
    int pipe_fds[2] = { -1, -1 };

    argv[argc++] = prog;
    va_start(args, prog);
    while (argc < 31) {
        const char *arg = va_arg(args, const char *);
        argv[argc++] = arg;
        if (arg == NULL)
            break;
    }
    va_end(args);
    argv[argc] = NULL;

    if (output && output_size > 0) {
        if (pipe(pipe_fds) < 0)
            return -1;
    }

    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (pipe_fds[0] >= 0) {
            close(pipe_fds[0]);
            dup2(pipe_fds[1], STDOUT_FILENO);
            close(pipe_fds[1]);
        }
        execvp(prog, (char *const *)argv);
        abort();
    }

    if (pipe_fds[0] >= 0) {
        close(pipe_fds[1]);
        ssize_t n = read(pipe_fds[0], output, output_size - 1);
        close(pipe_fds[0]);
        if (n < 0)
            n = 0;
        output[n] = '\0';
    }

    int status;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    if (!WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

#define cmd(...)                                                               \
    ({                                                                         \
        char _d[1];                                                            \
        cmd_output(_d, 0, __VA_ARGS__);                                        \
    })

static int create_tmux_tty(const char *session_name)
{
    char tty_path[256];
    char wait_cmd[128];

    snprintf(wait_cmd, sizeof(wait_cmd), "waitpid %d", (int)getpid());
    if (cmd("tmux", "new-session", "-d", "-s", session_name, "sh", "-c",
            wait_cmd, NULL) != 0)
        return -1;

    char hook_cmd[128];
    snprintf(hook_cmd, sizeof(hook_cmd), "run-shell 'kill -WINCH %d'",
             (int)getpid());
    cmd("tmux", "set-hook", "-g", "client-resized", hook_cmd, NULL);

    if (cmd_output(tty_path, sizeof(tty_path), "tmux", "display-message", "-p",
                   "-t", session_name, "#{pane_tty}", NULL) != 0)
        return -1;
    tty_path[strcspn(tty_path, "\n")] = '\0';

    return open(tty_path, O_RDWR);
}

static int mkfifo_if_needed(const char *path)
{
    if (mkfifo(path, 0666) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int create_fifo_inout(const char *fifo_in, const char *fifo_out,
                             int *input_fd, int *output_fd)
{
    if (mkfifo_if_needed(fifo_in) < 0)
        return -1;
    if (mkfifo_if_needed(fifo_out) < 0)
        return -1;

    int in_fd = open(fifo_in, O_RDONLY | O_NONBLOCK);
    if (in_fd < 0)
        return -1;

    int out_fd = open(fifo_out, O_RDWR | O_NONBLOCK);
    if (out_fd < 0) {
        close(in_fd);
        return -1;
    }

    *input_fd = in_fd;
    *output_fd = out_fd;
    return 0;
}

int main(int argc, char *const argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s ROOT_DIR COMMAND [ARGS...]\n", argv[0]);
        return 1;
    }

    const char *root_dir = argv[1];
    KrunError err = NULL;

    TRY(krun_init_log(KRUN_LOG_TARGET_DEFAULT, KRUN_LOG_LEVEL_WARN,
                      KRUN_LOG_STYLE_AUTO, &err));

    KrunConsoleBuilder console_builder = krun_console_device_builder();

    const int num_consoles = 3;
    for (int i = 0; i < num_consoles; i++) {
        char session_name[64];
        char port_name[64];
        snprintf(session_name, sizeof(session_name), "krun-console-%d", i + 1);
        snprintf(port_name, sizeof(port_name), "console-%d", i + 1);

        int tmux_fd = create_tmux_tty(session_name);
        if (tmux_fd < 0) {
            perror("create_tmux_tty");
            return 1;
        }
        uint32_t port_index = 0;
        TRY(krun_console_builder_add_tty_port(console_builder,
                                              KRUN_STR(port_name), tmux_fd,
                                              &port_index, &err));
        (void)port_index;
    }

    int in_fd, out_fd;
    if (create_fifo_inout("/tmp/consoles_example_in",
                          "/tmp/consoles_example_out", &in_fd, &out_fd) < 0) {
        perror("create_fifo_inout");
        return 1;
    }
    uint32_t fifo_port = 0;
    TRY(krun_console_builder_add_inout_port(console_builder,
                                            KRUN_STR("fifo_inout"), in_fd,
                                            out_fd, &fifo_port, &err));
    (void)fifo_port;

    fprintf(stderr, "\n=== Console ports configured ===\n");
    for (int i = 0; i < num_consoles; i++) {
        fprintf(stderr, "  console-%d: tmux attach -t krun-console-%d\n",
                i + 1, i + 1);
    }
    fprintf(stderr, "  fifo_inout: /tmp/consoles_example_in (host->guest)\n");
    fprintf(stderr, "  fifo_inout: /tmp/consoles_example_out (guest->host)\n");
    fprintf(stderr, "================================\n\n");

    TRY(KrunConsoleDevice console =
            krun_console_builder_build(console_builder, &err));

    KrunInitBuilder config_builder = krun_init_config_builder();
    KrunStr guest_args[argc - 1];
    for (int i = 2; i < argc; i++)
        guest_args[i - 2] = KRUN_STR(argv[i]);
    krun_init_builder_args(&config_builder, guest_args, (size_t)(argc - 2));
    krun_init_builder_workdir(&config_builder, KRUN_STR("/"));
    KrunInitConfig config = krun_init_builder_build(&config_builder);

    TRY(KrunFsDevice rootfs = krun_fs_device_new(
            KRUN_STR("/dev/root"), KRUN_STR(root_dir), &err));
    TRY(KrunPayload payload = krun_payload_load_krunfw(&err));

    KrunFsOverlay overlay = krun_fs_overlay_new();
    KrunInitError ierr = NULL;
    if (krun_init_config_apply(config, NULL, overlay, payload, &ierr) !=
        KRUN_RESULT_SUCCESS) {
        flockfile(stderr);
        fprintf(stderr, "krun_init_config_apply failed: ");
        if (ierr) {
            krun_init_error_message(ierr, &stderr_writer_init);
            krun_init_error_destroy(ierr);
        }
        fputc('\n', stderr);
        funlockfile(stderr);
        return 1;
    }
    krun_fs_device_set_overlay(rootfs, overlay);

    TRY(KrunBalloonDevice balloon = krun_balloon_device_new(&err));
    TRY(KrunRngDevice rng = krun_rng_device_new(&err));

    KrunMmioDeviceManager devices = krun_mmio_device_manager_new();
    krun_mmio_device_manager_add(devices, rootfs);
    krun_mmio_device_manager_add(devices, console);
    krun_mmio_device_manager_add(devices, balloon);
    krun_mmio_device_manager_add(devices, rng);

    KrunVmmBuilder builder = krun_vmm_builder_new();
    TRY(krun_vmm_builder_vcpus(&builder, 4, &err));
    TRY(krun_vmm_builder_ram_mib(&builder, 4096, &err));
    krun_vmm_builder_payload(&builder, payload);
    krun_vmm_builder_devices(&builder, devices);

    TRY(KrunVmm vmm = krun_vmm_builder_build(&builder, &err));
    krun_vmm_run(vmm);
    krun_vmm_destroy(vmm);
    krun_init_config_destroy(config);
    return 0;
}
