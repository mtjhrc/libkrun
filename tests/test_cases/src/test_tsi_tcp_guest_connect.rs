use macros::{guest, host};
use std::io::{ErrorKind, Read};
use std::mem;
use std::net::TcpStream;
use std::time::Duration;

pub struct TestTsiHijackTCP;

fn stream_expect_msg(stream: &mut TcpStream, expected: &[u8]) {
    let mut buf = vec![0; expected.len()];
    stream.read_exact(&mut buf[..]).unwrap();
    assert_eq!(&buf[..], expected);
}

fn stream_expect_wouldblock(stream: &mut TcpStream) {
    stream.set_nonblocking(true).unwrap();
    let err = stream.read(&mut [0u8; 1]).unwrap_err();
    stream.set_nonblocking(false).unwrap();
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
}

fn stream_set_timeouts(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .unwrap();
}

#[host]
mod host {
    use super::*;

    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32};
    use crate::{Test, TestSetup};
    use krun_sys::*;
    use std::ffi::CStr;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    fn server(listener: TcpListener) {
        //thread::sleep(Duration::from_secs(2));
        let (mut stream, _addr) = listener.accept().unwrap();
        eprintln!("accepted a new connection");
        stream_set_timeouts(&mut stream);
        stream.write_all(b"ping!").unwrap();
        stream_expect_msg(&mut stream, b"pong!");
        stream_expect_wouldblock(&mut stream);
        stream.write_all(b"bye!").unwrap();
        mem::forget(listener);
    }

    impl Test for TestTsiHijackTCP {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            unsafe {
                krun_call!(krun_set_log_level(0));
            }
            //thread::sleep(Duration::from_secs(2));
            eprintln!("hello?");
            let listener = TcpListener::bind("0.0.0.0:8121").unwrap();
            eprintln!("listening!");
            thread::spawn(move || server(listener));
            thread::sleep(Duration::from_secs(1));

            eprintln!("spawned server");
            unsafe {
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use std::fs::File;
    use super::*;
    use crate::Test;
    use std::io::{stderr, BufReader, Write};
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd;
    use std::str::FromStr;
    use std::thread;
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, SockaddrIn};

    impl Test for TestTsiHijackTCP {
        fn in_guest(self: Box<Self>) {
            //std::fs::write("/proc/sys/kernel/printk", "8").unwrap();
            //let log_lvl = std::fs::read_to_string("/proc/sys/kernel/printk").unwrap();
            //eprintln!("log level: {:?}", log_lvl);
            //eprintln!("cmdline: {:?}", std::fs::read_to_string("/proc/cmdline").unwrap());
            eprintln!("in guest");
            //thread::sleep(Duration::from_millis(1000));

            /*
            let addr = SocketAddr::from_str("127.0.0.1:8121").unwrap();
            let mut stream = match TcpStream::connect(&addr) {
               //TcpStream::connect_timeout(&addr, Duration::from_secs(10))
               Ok(stream) => stream,
               Err(err) => {
                   let raw_err = err.raw_os_error().unwrap();
                   eprintln!("connect error: {err}, ({raw_err})");
                   return;
               }
           };*/
            //thread::sleep(Duration::from_secs(2));
            /*
            let sock = socket(AddressFamily::Inet, SockType::Stream, SockFlag::empty(), None).unwrap();
            let addr = nix::sys::socket::SockaddrIn::new(127, 0,0,1, 8121);
            connect(sock.as_raw_fd(), &addr).unwrap();
            let mut stream = TcpStream::from(sock);
            */

            stream_set_timeouts(&mut stream);
            eprintln!("guest connected!");
            stderr().flush();
            stream_expect_msg(&mut stream, b"ping!");
            stream_expect_wouldblock(&mut stream);
            stream.write_all(b"pong!").unwrap();
            stream_expect_msg(&mut stream, b"bye!");
            println!("OK");
        }
    }
}
