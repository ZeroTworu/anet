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
    #[cfg(target_os = "linux")]
    {
        use libc::{IPPROTO_TCP, TCP_CORK, TCP_QUICKACK, setsockopt};
        use socket2::{Socket, TcpKeepalive};
        use std::os::unix::io::FromRawFd;

        let raw_fd = stream.as_raw_fd();
        let socket = unsafe { Socket::from_raw_fd(raw_fd) };

        // Поэкспериментируем с разными размерами буферов
        // socket.set_send_buffer_size(1024 * 1024)?;
        // socket.set_recv_buffer_size(1024 * 1024)?;

        // Включаем TCP_NODELAY для уменьшения задержки
        socket.set_tcp_nodelay(true)?;
        socket.set_nonblocking(true)?;
        socket.set_linger(Some(Duration::from_secs(30)))?;

        // Настройка keepalive
        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(300))
            .with_interval(Duration::from_secs(15))
            .with_retries(8);

        socket.set_tcp_keepalive(&keepalive)?;

        // Включаем TCP QuickACK для быстрого подтверждения пакетов
        let quickack: i32 = 1;
        unsafe {
            setsockopt(
                raw_fd,
                IPPROTO_TCP,
                TCP_QUICKACK,
                &quickack as *const _ as *const _,
                size_of::<i32>() as _,
            );
        }

        // Настройка Cork/NoDelay в зависимости от типа трафика
        let cork: i32 = 0;
        unsafe {
            setsockopt(
                raw_fd,
                IPPROTO_TCP,
                TCP_CORK,
                &cork as *const _ as *const _,
                size_of::<i32>() as _,
            );
        }
        std::mem::forget(socket);
    }

    Ok(())
}
