use crate::datagram_tester::DatagramTester;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::thread;
use std::time::Duration;

fn set_timeouts(socket: &UdpSocket) {
    socket
        .set_read_timeout(Some(Duration::from_millis(2000)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_millis(2000)))
        .unwrap();
}

// This function sets socket options on a UDP socket, which will trigger the
// null pointer dereference bug in tsi_dgram_setsockopt if not properly fixed
fn set_socket_options(socket: &UdpSocket) {
    // Set SO_REUSEADDR - this is a SOL_SOCKET level option that would trigger
    // the bug in the unfixed kernel
    socket.set_nonblocking(false).unwrap();

    // Setting broadcast option - another SOL_SOCKET level option
    // This triggers setsockopt with SOL_SOCKET level
    socket.set_broadcast(true).unwrap();
    socket.set_broadcast(false).unwrap();

    // Set TTL - another common socket option
    socket.set_ttl(64).unwrap();
}

#[derive(Debug, Copy, Clone)]
pub struct UdpTester {
    port: u16,
}

impl UdpTester {
    pub const fn new(port: u16) -> Self {
        Self { port }
    }

    pub fn create_server_socket(&self) -> UdpSocket {
        // Bind to 0.0.0.0:port on the host, just like TCP test
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), self.port))
            .unwrap();
        set_timeouts(&socket);
        // This is the critical call that triggers the bug!
        set_socket_options(&socket);
        socket
    }

    pub fn run_server(&self, socket: UdpSocket) {
        let tester = DatagramTester::new(socket);
        tester.run_server();
    }

    pub fn run_client(&self) {
        // Give server time to start
        thread::sleep(Duration::from_millis(100));

        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)).unwrap();
        set_timeouts(&socket);

        // This is the CRITICAL call that triggers the kernel NULL pointer dereference bug!
        // On an unfixed kernel, this will cause a kernel panic/oops
        // This tests the setsockopt bug fix at tsi_dgram_setsockopt:971
        set_socket_options(&socket);

        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), self.port);

        // DON'T connect - UDP connect will succeed on inet and packets go to wrong place
        // Instead, use send_to() directly which will use HYBRID fallback to VSOCK
        let tester = DatagramTester::new(socket);
        tester.run_client(server_addr);
    }
}
