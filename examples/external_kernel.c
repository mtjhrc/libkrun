/*
 * Boot an external kernel with libkrun v2 API.
 *
 * Usage: external_kernel [OPTIONS] KERNEL
 *
 * Optional: --boot-disk, --data-disk, --kernel-cmdline, --net=passt,
 * --passt-socket. Nested virt and initrd are not yet exposed in the v2 API.
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <libkrun.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Same bitset as libkrun::COMPAT_NET_FEATURES (not yet exported via ffier). */
#define COMPAT_NET_FEATURES                                                    \
    ((1u << 0) | (1u << 1) | (1u << 7) | (1u << 10) | (1u << 11) | (1u << 14))

#if defined(__x86_64__)
#define KERNEL_FORMAT KRUN_KERNEL_FORMAT_ELF
#else
#define KERNEL_FORMAT KRUN_KERNEL_FORMAT_RAW
#endif

enum net_mode {
    NET_MODE_PASST = 0,
    NET_MODE_TSI,
};

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
        return -1;                                                             \
    }

static void print_help(char *const name)
{
    fprintf(stderr,
            "Usage: %s [OPTIONS] KERNEL\n"
            "OPTIONS:\n"
            "        -b    --boot-disk           Path to a boot disk in raw format\n"
            "        -c    --kernel-cmdline      Kernel command line\n"
            "        -d    --data-disk           Path to a data disk in raw format\n"
            "        -h    --help                Show help\n"
            "              --net=NET_MODE        Set network mode (tsi|passt)\n"
            "              --passt-socket=PATH   Connect to passt socket at PATH\n"
            "\n"
            "Not yet supported in v2: --initrd, --nested\n"
            "\n"
#if defined(__x86_64__)
            "KERNEL: path to the kernel image in ELF format\n",
#else
            "KERNEL: path to the kernel image in RAW format\n",
#endif
            name);
}

static const struct option long_options[] = {
    { "boot-disk", required_argument, NULL, 'b' },
    { "kernel-cmdline", required_argument, NULL, 'c' },
    { "data-disk", required_argument, NULL, 'd' },
    { "help", no_argument, NULL, 'h' },
    { "net", required_argument, NULL, 'N' },
    { "passt-socket", required_argument, NULL, 'P' },
    { NULL, 0, NULL, 0 },
};

struct cmdline {
    bool show_help;
    enum net_mode net_mode;
    char const *boot_disk;
    char const *data_disk;
    char const *passt_socket_path;
    char const *kernel_path;
    char const *kernel_cmdline;
};

static bool parse_cmdline(int argc, char *const argv[], struct cmdline *cmdline)
{
    *cmdline = (struct cmdline){
        .show_help = false,
        .net_mode = NET_MODE_TSI,
        .passt_socket_path = "/tmp/network.sock",
        .boot_disk = NULL,
        .data_disk = NULL,
        .kernel_path = NULL,
        .kernel_cmdline = "",
    };

    int option_index = 0;
    int c;
    while ((c = getopt_long(argc, argv, "+hb:c:d:", long_options,
                            &option_index)) != -1) {
        switch (c) {
        case 'b':
            cmdline->boot_disk = optarg;
            break;
        case 'c':
            cmdline->kernel_cmdline = optarg;
            break;
        case 'd':
            cmdline->data_disk = optarg;
            break;
        case 'h':
            cmdline->show_help = true;
            return true;
        case 'N':
            if (strcasecmp(optarg, "passt") == 0)
                cmdline->net_mode = NET_MODE_PASST;
            else if (strcasecmp(optarg, "tsi") == 0)
                cmdline->net_mode = NET_MODE_TSI;
            else {
                fprintf(stderr, "unknown net mode: %s\n", optarg);
                return false;
            }
            break;
        case 'P':
            cmdline->passt_socket_path = optarg;
            break;
        case '?':
            return false;
        default:
            return false;
        }
    }

    if (optind <= argc - 1) {
        cmdline->kernel_path = argv[optind];
        return true;
    }

    fprintf(stderr, "Missing KERNEL argument\n");
    return false;
}

static int start_passt(void)
{
    int socket_fds[2];
    const int PARENT = 0;
    const int CHILD = 1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds) < 0) {
        perror("socketpair");
        return -1;
    }

    int pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        close(socket_fds[PARENT]);
        char fd_as_str[16];
        snprintf(fd_as_str, sizeof(fd_as_str), "%d", socket_fds[CHILD]);
        execlp("passt", "passt", "-f", "--fd", fd_as_str, NULL);
        perror("execlp passt");
        _exit(1);
    }

    close(socket_fds[CHILD]);
    return socket_fds[PARENT];
}

int main(int argc, char *const argv[])
{
    KrunError err = NULL;
    struct cmdline cmdline;

    if (!parse_cmdline(argc, argv, &cmdline)) {
        putchar('\n');
        print_help(argv[0]);
        return -1;
    }
    if (cmdline.show_help) {
        print_help(argv[0]);
        return 0;
    }

    TRY(krun_init_log(KRUN_LOG_TARGET_DEFAULT, KRUN_LOG_LEVEL_OFF,
                      KRUN_LOG_STYLE_AUTO, &err));

    TRY(KrunPayload payload = krun_payload_load_external(
            KRUN_STR(cmdline.kernel_path), KERNEL_FORMAT,
            KRUN_STR(cmdline.kernel_cmdline), &err));

    KrunConsoleBuilder console_builder = krun_console_device_builder();
    TRY(krun_console_builder_add_default_console(
            console_builder, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
            &err));
    TRY(KrunConsoleDevice console =
            krun_console_builder_build(console_builder, &err));

    TRY(KrunBalloonDevice balloon = krun_balloon_device_new(&err));
    TRY(KrunRngDevice rng = krun_rng_device_new(&err));

    KrunMmioDeviceManager devices = krun_mmio_device_manager_new();
    krun_mmio_device_manager_add(devices, console);
    krun_mmio_device_manager_add(devices, balloon);
    krun_mmio_device_manager_add(devices, rng);

    if (cmdline.boot_disk) {
        TRY(KrunBlockDevice boot = krun_block_device_new(
                KRUN_STR("boot"), KRUN_STR(cmdline.boot_disk), false, &err));
        krun_mmio_device_manager_add(devices, boot);
    }
    if (cmdline.data_disk) {
        TRY(KrunBlockDevice data = krun_block_device_new(
                KRUN_STR("data"), KRUN_STR(cmdline.data_disk), false, &err));
        krun_mmio_device_manager_add(devices, data);
    }

    if (cmdline.net_mode == NET_MODE_PASST) {
        uint8_t mac[] = { 0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee };
        KrunBytes mac_bytes = { .data = mac, .len = sizeof(mac) };
        if (cmdline.passt_socket_path != NULL) {
            TRY(KrunNetDevice net = krun_net_device_new_unixstream_path(
                    KRUN_STR("net0"), KRUN_STR(cmdline.passt_socket_path),
                    mac_bytes, COMPAT_NET_FEATURES, &err));
            krun_mmio_device_manager_add(devices, net);
        } else {
            int passt_fd = start_passt();
            if (passt_fd < 0)
                return -1;
            TRY(KrunNetDevice net = krun_net_device_new_unixstream_fd(
                    KRUN_STR("net0"), passt_fd, mac_bytes, COMPAT_NET_FEATURES,
                    &err));
            krun_mmio_device_manager_add(devices, net);
        }
    }

    KrunVmmBuilder builder = krun_vmm_builder_new();
    TRY(krun_vmm_builder_vcpus(&builder, 2, &err));
    TRY(krun_vmm_builder_ram_mib(&builder, 2048, &err));
    krun_vmm_builder_payload(&builder, payload);
    krun_vmm_builder_devices(&builder, devices);

    TRY(KrunVmm vmm = krun_vmm_builder_build(&builder, &err));
    krun_vmm_run(vmm);
    return 0;
}
