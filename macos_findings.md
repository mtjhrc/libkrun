# macOS sendmsg_x / recvmsg_x API Reference

**Undocumented** private Apple syscalls for batch datagram send/receive, similar to Linux's `sendmmsg`/`recvmmsg`. These are not part of any public API and may change without notice.

Source: https://github.com/nirs/vmnet-helper/blob/main/socket_x.h (reverse-engineered definitions)

## API Signatures

```c
ssize_t sendmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);
ssize_t recvmsg_x(int s, struct msghdr_x *msgp, u_int cnt, int flags);

struct msghdr_x {
    void         *msg_name;       // optional address
    socklen_t     msg_namelen;    // address length
    struct iovec *msg_iov;        // scatter/gather array
    int           msg_iovlen;     // # elements in msg_iov
    void         *msg_control;    // ancillary data
    socklen_t     msg_controllen; // ancillary data length
    int           msg_flags;      // flags on received message
    size_t        msg_datalen;    // [OUT] bytes transferred
};
```

## Key Behavioral Findings

### Return Values

| Function | Success | Partial Success | Error |
|----------|---------|-----------------|-------|
| `sendmsg_x` | N (messages sent) | N < cnt (partial) | -1 |
| `recvmsg_x` | N (messages received) | N < cnt (normal) | -1 |

### msg_datalen Field

| Context | Behavior |
|---------|----------|
| `sendmsg_x` output | **Always 0** - not populated on send |
| `recvmsg_x` output | Set to actual bytes received per message |

### Partial Sends (sendmsg_x)

When the socket buffer cannot fit all messages:

1. **Return value indicates success count**: If you pass 20 messages and get 9, messages at indices 0-8 were sent
2. **Messages are sent in order**: First N messages succeed, remaining are not sent
3. **No partial message sends**: Each datagram is sent completely or not at all
4. **Immediate retry returns `ENOBUFS`** (error 55) if buffer still full

### Supported Flags

| Flag | Support |
|------|---------|
| `MSG_DONTWAIT` | Supported - non-blocking operation |
| Other flags | Not documented/tested |

### Error Codes

| Error | Code | Condition |
|-------|------|-----------|
| `EBADF` | 9 | Invalid or closed file descriptor |
| `EAGAIN` | 35 | No data available (non-blocking recv) |
| `ENOBUFS` | 55 | No buffer space (non-blocking send, buffer full) |
| `EMSGSIZE` | 40 | Message too large for socket buffer |

## Usage Patterns

### Basic Batch Send

```rust
let mut hdrs: Vec<msghdr_x> = /* prepare headers */;

let sent = unsafe {
    sendmsg_x(fd, hdrs.as_ptr(), hdrs.len() as u32, 0)
};

if sent < 0 {
    return Err(io::Error::last_os_error());
}
// sent messages: 0..(sent as usize)
```

### Basic Batch Receive

```rust
let mut hdrs: Vec<msghdr_x> = /* prepare headers with buffers */;

let received = unsafe {
    recvmsg_x(fd, hdrs.as_mut_ptr(), hdrs.len() as u32, 0)
};

if received < 0 {
    return Err(io::Error::last_os_error());
}

for i in 0..(received as usize) {
    let len = hdrs[i].msg_datalen;  // actual bytes received
    // process buffer[i][..len]
}
```

### Handling Partial Sends with Retry

```rust
fn send_all(fd: RawFd, hdrs: &[msghdr_x]) -> io::Result<()> {
    let mut offset = 0;

    while offset < hdrs.len() {
        let remaining = hdrs.len() - offset;

        let sent = unsafe {
            sendmsg_x(
                fd,
                hdrs[offset..].as_ptr(),
                remaining as u32,
                MSG_DONTWAIT,
            )
        };

        if sent < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) | Some(55 /* ENOBUFS */) => {
                    // Buffer full - wait for socket to become writable
                    // (use poll/kqueue/select here)
                    poll_writable(fd)?;
                    continue;
                }
                _ => return Err(err),
            }
        }

        offset += sent as usize;
    }

    Ok(())
}
```

## Constraints (from reverse engineering / vmnet-helper)

### sendmsg_x Input Requirements
For each `msghdr_x`:
- `msg_name` must be NULL (or valid destination for unconnected sockets)
- `msg_namelen` must be 0 (or valid length)
- `msg_control` must be NULL
- `msg_controllen` must be 0
- `msg_flags` must be 0
- `msg_datalen` must be 0

### recvmsg_x Input Requirements
For each `msghdr_x`:
- `msg_flags` must be 0 on input (set by kernel on output)

## Comparison with Linux sendmmsg/recvmmsg

| Feature | macOS sendmsg_x | Linux sendmmsg |
|---------|-----------------|----------------|
| Header struct | `msghdr_x` | `mmsghdr` (contains `msghdr` + `msg_len`) |
| Bytes sent field | `msg_datalen` (always 0) | `msg_len` (populated) |
| Partial send tracking | Return value only | Return value + `msg_len` per message |
| Flags | Only `MSG_DONTWAIT` | Full flags support |

## Integration Notes for libkrun

1. **Batch size**: Unix domain sockets on macOS have small default buffers (~2KB). With typical packet sizes, expect 5-10 messages per batch before buffer fills.

2. **Non-blocking recommended**: Use `MSG_DONTWAIT` and handle `ENOBUFS`/`EAGAIN` with event loop integration (kqueue).

3. **No ancillary data**: `msg_control`/`msg_controllen` must be zero - cannot pass file descriptors via these APIs.

4. **Message ordering**: Guaranteed FIFO - messages 0..N are sent/received in order.

5. **Atomicity**: Each datagram in the batch is atomic - no partial datagram sends.
