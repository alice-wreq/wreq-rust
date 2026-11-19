use std::{
    marker::{PhantomData, Unpin},
    task::{self, Poll},
};

use bytes::BytesMut;
use http::{HeaderMap, HeaderValue, Uri};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tower::{BoxError, Service};

use super::Tunneling;
use crate::ext::UriExt;

/// Tunnel Proxy via HTTP CONNECT
///
/// This is a connector that can be used by the `Client`. It wraps
/// another connector, and after getting an underlying connection, it creates
/// an HTTP CONNECT tunnel over it.
#[derive(Debug)]
pub struct TunnelConnector<C> {
    headers: Headers,
    inner: C,
    proxy_dst: Uri,
}

#[derive(Clone, Debug)]
enum Headers {
    Empty,
    Auth(HeaderValue),
    Extra(HeaderMap),
}

#[derive(Debug)]
pub enum TunnelError {
    ConnectFailed(BoxError),
    Io(std::io::Error),
    Parse(httparse::Error),
    MissingHost,
    ProxyAuthRequired,
    TunnelUnexpectedEof,
    TunnelUnsuccessful(Option<u16>),
    ProxyIpDenied,
}

impl<C> TunnelConnector<C> {
    /// Create a new tunnel connector.
    ///
    /// This wraps an underlying connector, and stores the address of a
    /// tunneling proxy server.
    ///
    /// A `TunnelConnector` can then be called with any destination. The `proxy_dst` passed to
    /// `call` will not be used to create the underlying connection, but will
    /// be used in an HTTP CONNECT request sent to the proxy destination.
    pub fn new(proxy_dst: Uri, connector: C) -> Self {
        Self {
            headers: Headers::Empty,
            inner: connector,
            proxy_dst,
        }
    }

    /// Add `proxy-authorization` header value to the CONNECT request.
    pub fn with_auth(mut self, mut auth: HeaderValue) -> Self {
        // just in case the user forgot
        auth.set_sensitive(true);
        match self.headers {
            Headers::Empty => {
                self.headers = Headers::Auth(auth);
            }
            Headers::Auth(ref mut existing) => {
                *existing = auth;
            }
            Headers::Extra(ref mut extra) => {
                extra.insert(http::header::PROXY_AUTHORIZATION, auth);
            }
        }

        self
    }

    /// Add extra headers to be sent with the CONNECT request.
    ///
    /// If existing headers have been set, these will be merged.
    pub fn with_headers(mut self, mut headers: HeaderMap) -> Self {
        match self.headers {
            Headers::Empty => {
                self.headers = Headers::Extra(headers);
            }
            Headers::Auth(auth) => {
                headers
                    .entry(http::header::PROXY_AUTHORIZATION)
                    .or_insert(auth);
                self.headers = Headers::Extra(headers);
            }
            Headers::Extra(ref mut extra) => {
                extra.extend(headers);
            }
        }

        self
    }
}

impl<C> Service<Uri> for TunnelConnector<C>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Response: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
{
    type Response = C::Response;
    type Error = TunnelError;
    type Future = Tunneling<C::Future, C::Response, Self::Error>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(Into::into)
            .map_err(TunnelError::ConnectFailed)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let connecting = self.inner.call(self.proxy_dst.clone());
        let headers = self.headers.clone();

        Tunneling {
            fut: Box::pin(async move {
                let conn = connecting
                    .await
                    .map_err(Into::into)
                    .map_err(TunnelError::ConnectFailed)?;
                tunnel(
                    conn,
                    dst.host().ok_or(TunnelError::MissingHost)?,
                    dst.port_or_default(),
                    &headers,
                )
                .await
            }),
            _marker: PhantomData,
        }
    }
}

async fn tunnel<T>(mut conn: T, host: &str, port: u16, headers: &Headers) -> Result<T, TunnelError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = format!(
        "\
         CONNECT {host}:{port} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         "
    )
    .into_bytes();

    match headers {
        Headers::Auth(auth) => {
            buf.extend_from_slice(b"Proxy-Authorization: ");
            buf.extend_from_slice(auth.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        Headers::Extra(extra) => {
            for (name, value) in extra {
                buf.extend_from_slice(name.as_str().as_bytes());
                buf.extend_from_slice(b": ");
                buf.extend_from_slice(value.as_bytes());
                buf.extend_from_slice(b"\r\n");
            }
        }
        Headers::Empty => (),
    }

    // headers end
    buf.extend_from_slice(b"\r\n");

    conn.write_all(&buf).await.map_err(TunnelError::Io)?;
    conn.flush().await.map_err(TunnelError::Io)?;

    let mut buf = BytesMut::with_capacity(8192);

    loop {
        if conn.read_buf(&mut buf).await.map_err(TunnelError::Io)? == 0 {
            return Err(TunnelError::TunnelUnexpectedEof);
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut res = httparse::Response::new(&mut headers);
        match res.parse(&buf).map_err(TunnelError::Parse)? {
            httparse::Status::Partial => continue,
            httparse::Status::Complete(end) => match res.code {
                Some(200) => return Ok(conn),
                Some(407) => return Err(TunnelError::ProxyAuthRequired),
                Some(512)
                    if res.reason == Some("auth ip err")
                        || has_ip_denial(&mut conn, res.headers, &buf[end..]).await =>
                {
                    return Err(TunnelError::ProxyIpDenied);
                }
                status => return Err(TunnelError::TunnelUnsuccessful(status)),
            },
        }
    }
}

// Recognize the provider's diagnostic without exposing arbitrary proxy response bodies.
async fn has_ip_denial<T: AsyncRead + Unpin>(
    conn: &mut T,
    headers: &[httparse::Header<'_>],
    buffered: &[u8],
) -> bool {
    use futures_util::future::{Either, select};
    use wreq_proto::rt::Timer as _;

    const MESSAGE: &[u8; 11] = b"auth ip err";
    let mut lengths = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"));
    if lengths.next().map(|h| h.value) != Some(b"11")
        || lengths.next().is_some()
        || headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return false;
    }
    if buffered.len() >= MESSAGE.len() {
        return buffered.starts_with(MESSAGE);
    }
    if !MESSAGE.starts_with(buffered) {
        return false;
    }
    let timer = crate::rt::Timer::default();
    if timer.is_empty() {
        return false;
    }
    let mut tail = [0; MESSAGE.len()];
    let tail = &mut tail[..MESSAGE.len() - buffered.len()];
    let deadline = timer.sleep(std::time::Duration::from_millis(100));
    matches!(
        select(std::pin::pin!(conn.read_exact(tail)), deadline).await,
        Either::Left((Ok(_), _))
    ) && tail == &MESSAGE[buffered.len()..]
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tunnel error: ")?;

        match self {
            TunnelError::ProxyIpDenied => f.write_str("unsuccessful (status 512): auth ip err"),
            TunnelError::MissingHost => f.write_str("missing destination host"),
            TunnelError::ProxyAuthRequired => f.write_str("proxy authorization required"),
            TunnelError::Parse(_) => f.write_str("invalid proxy response"),
            TunnelError::TunnelUnexpectedEof => f.write_str("unexpected end of file"),
            TunnelError::TunnelUnsuccessful(Some(status)) => {
                write!(f, "unsuccessful (status {status})")
            }
            TunnelError::TunnelUnsuccessful(None) => f.write_str("unsuccessful"),
            TunnelError::ConnectFailed(_) => f.write_str("failed to create underlying connection"),
            TunnelError::Io(_) => f.write_str("io error establishing tunnel"),
        }
    }
}

impl std::error::Error for TunnelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TunnelError::Io(e) => Some(e),
            TunnelError::Parse(e) => Some(e),
            TunnelError::ConnectFailed(e) => Some(&**e),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "tokio-rt"))]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn recognizes_only_confirmed_ip_denials_without_waiting_for_eof() {
        let length = httparse::Header {
            name: "Content-Length",
            value: b"11",
        };
        let (mut reader, mut writer) = tokio::io::duplex(32);
        // With no declared body even a permanently open connection must be ready on first poll.
        use futures_util::FutureExt as _;
        assert_eq!(
            has_ip_denial(&mut reader, &[], &[]).now_or_never(),
            Some(false)
        );
        assert!(!has_ip_denial(&mut reader, &[length], b"private msg").await);
        let send = async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            writer.write_all(b"ip err").await.unwrap();
        };
        let lengths = [length];
        let (recognized, ()) = tokio::join!(has_ip_denial(&mut reader, &lengths, b"auth "), send);
        assert!(recognized);
        let timeout = tokio::time::timeout(Duration::from_secs(1), async {
            has_ip_denial(&mut reader, &[length], &[]).await
        });
        assert!(
            !timeout
                .await
                .expect("missing body must not block the refusal")
        );
    }
}
