//! Concrete enum listener. No `dyn` — dispatch by match.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::config::env::Environment;

#[derive(Debug, Error)]
pub enum ListenerError {
    #[error("TCP listener forbidden in production")]
    TcpForbiddenInProduction,
    #[error("bind failed: {0}")]
    BindFailed(String),
    #[error("vsock only supported on linux")]
    VsockUnsupported,
}

#[derive(Clone, Debug)]
pub enum ListenerKind {
    Vsock { port: u32 },
    Tcp { addr: std::net::SocketAddr },
}

pub enum ConcreteListener {
    Tcp(TcpListener),
    #[cfg(target_os = "linux")]
    Vsock(tokio_vsock::VsockListener),
}

pub enum ConnStream {
    Tcp(TcpStream),
    #[cfg(target_os = "linux")]
    Vsock(tokio_vsock::VsockStream),
}

impl AsyncRead for ConnStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(target_os = "linux")]
            ConnStream::Vsock(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ConnStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ConnStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(target_os = "linux")]
            ConnStream::Vsock(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(target_os = "linux")]
            ConnStream::Vsock(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(target_os = "linux")]
            ConnStream::Vsock(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl ConcreteListener {
    pub async fn accept(&mut self) -> io::Result<(ConnStream, std::net::SocketAddr)> {
        match self {
            ConcreteListener::Tcp(l) => {
                let (s, addr) = l.accept().await?;
                Ok((ConnStream::Tcp(s), addr))
            }
            #[cfg(target_os = "linux")]
            ConcreteListener::Vsock(l) => {
                let (s, _vaddr) = l.accept().await?;
                // synthetic SocketAddr for logging
                let addr = "0.0.0.0:0".parse().unwrap();
                Ok((ConnStream::Vsock(s), addr))
            }
        }
    }

    pub fn is_vsock(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            matches!(self, ConcreteListener::Vsock(_))
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

pub async fn build_listener(
    kind: ListenerKind,
    env: Environment,
) -> Result<ConcreteListener, ListenerError> {
    match kind {
        ListenerKind::Tcp { addr } => {
            if env == Environment::Production {
                return Err(ListenerError::TcpForbiddenInProduction);
            }
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| ListenerError::BindFailed(e.to_string()))?;
            Ok(ConcreteListener::Tcp(listener))
        }
        ListenerKind::Vsock { port } => {
            #[cfg(target_os = "linux")]
            {
                use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
                let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))
                    .map_err(|e| ListenerError::BindFailed(e.to_string()))?;
                Ok(ConcreteListener::Vsock(listener))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = port;
                Err(ListenerError::VsockUnsupported)
            }
        }
    }
}
