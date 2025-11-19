use std::net::SocketAddr;

/// Generic trait for datagram socket operations.
/// This abstracts over UDP sockets, Unix datagram sockets, etc.
pub trait DatagramSocket {
    /// Send data to a specific address
    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize>;

    /// Receive data and return the sender's address
    fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
}

/// Implementation for std::net::UdpSocket
impl DatagramSocket for std::net::UdpSocket {
    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        std::net::UdpSocket::send_to(self, buf, addr)
    }

    fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        std::net::UdpSocket::recv_from(self, buf)
    }
}

/// Generic datagram tester that works with any datagram socket type.
/// Handles ping-pong communication pattern for testing.
pub struct DatagramTester<S> {
    socket: S,
}

impl<S: DatagramSocket> DatagramTester<S> {
    pub fn new(socket: S) -> Self {
        Self { socket }
    }

    /// Run the server side of the ping-pong test.
    /// Receives from any client, responds, and waits for acknowledgment.
    pub fn run_server(&self) {
        let mut buf = vec![0; 20];

        // Receive first message from client
        let (size, client_addr) = self.socket.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..size], b"ping!");

        // Send response back to client
        self.socket.send_to(b"pong!", client_addr).unwrap();

        // Receive final message
        let (size, _) = self.socket.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..size], b"done!");
    }

    /// Run the client side of the ping-pong test.
    /// Sends to server, waits for response, and sends acknowledgment.
    pub fn run_client(&self, server_addr: SocketAddr) {
        // Send initial message
        self.socket.send_to(b"ping!", server_addr).unwrap();

        // Wait for server response
        let mut buf = vec![0; 20];
        let (size, _from) = self.socket.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..size], b"pong!");

        // Send acknowledgment
        self.socket.send_to(b"done!", server_addr).unwrap();
    }
}
