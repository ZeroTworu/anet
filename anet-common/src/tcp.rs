#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock;

#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[cfg(unix)]
use std::time::Duration;

use tokio::net::TcpStream;

pub fn optimize_tcp_connection(stream: &TcpStream) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use socket2::{Socket, TcpKeepalive};
        use std::os::unix::io::FromRawFd;

        let raw_fd = stream.as_raw_fd();

        let socket = unsafe { Socket::from_raw_fd(raw_fd) };

        socket.set_recv_buffer_size(1024 * 1024)?;
        socket.set_send_buffer_size(1024 * 1024)?;

        socket.set_tcp_nodelay(true)?;

        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(10))
            .with_retries(3);
        socket.set_tcp_keepalive(&keepalive)?;
        socket.set_nonblocking(true)?;

        std::mem::forget(socket);
    }

    #[cfg(windows)]
    {
        let raw_socket = stream.as_raw_socket() as WinSock::SOCKET;

        let recv_buf_size: i32 = 1024 * 1024;
        let send_buf_size: i32 = 1024 * 1024;

        unsafe {
            WinSock::setsockopt(
                raw_socket,
                WinSock::SOL_SOCKET,
                WinSock::SO_RCVBUF,
                &recv_buf_size as *const _ as *const _,
                std::mem::size_of::<i32>() as i32,
            );

            WinSock::setsockopt(
                raw_socket,
                WinSock::SOL_SOCKET,
                WinSock::SO_SNDBUF,
                &send_buf_size as *const _ as *const _,
                std::mem::size_of::<i32>() as i32,
            );

            let nodelay: i32 = 1;
            WinSock::setsockopt(
                raw_socket,
                WinSock::IPPROTO_TCP,
                WinSock::TCP_NODELAY,
                &nodelay as *const _ as *const _,
                std::mem::size_of::<i32>() as i32,
            );

            let keepalive: u32 = 1;
            let keepalive_time: u32 = 60000;
            let keepalive_interval: u32 = 10000;

            WinSock::setsockopt(
                raw_socket,
                WinSock::SOL_SOCKET,
                WinSock::SO_KEEPALIVE,
                &keepalive as *const _ as *const _,
                std::mem::size_of::<u32>() as i32,
            );

            WinSock::setsockopt(
                raw_socket,
                WinSock::IPPROTO_TCP,
                WinSock::TCP_KEEPIDLE,
                &keepalive_time as *const _ as *const _,
                std::mem::size_of::<u32>() as i32,
            );

            WinSock::setsockopt(
                raw_socket,
                WinSock::IPPROTO_TCP,
                WinSock::TCP_KEEPINTVL,
                &keepalive_interval as *const _ as *const _,
                std::mem::size_of::<u32>() as i32,
            );
        }
    }

    Ok(())
}
