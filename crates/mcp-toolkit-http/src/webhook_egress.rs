//! # Guarded webhook HTTPS egress
//!
//! Send one immutable signed webhook attempt to a public HTTPS destination.
//! Enable `webhook-egress`; preparation remains independently I/O-free.
//!
//! ## Security boundaries
//! Every attempt resolves again, rejects the entire answer set if any address
//! is non-public, and gives an isolated HTTP client only those socket addresses.
//! The original hostname remains the TLS identity. Proxies, redirects, automatic
//! retries, decompression, connection reuse and HTTP/2 are disabled.
//!
//! This is not authorization or a delivery worker. Callers own current rights,
//! callback/principal binding, signing time, durable state, retry admission and
//! concurrency limits. A timeout or cancellation cannot retract bytes already
//! sent; receipt does not acknowledge source work. Errors and Debug omit secrets.
//!
//! System DNS cannot be forcibly cancelled. At most eight blocking lookups are
//! admitted process-wide; timed-out lookups retain their slot until the OS
//! returns and cannot start an HTTP request. Runtime shutdown can still wait for
//! OS resolution. See `docs/webhook-egress.md` for limits and test evidence.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use url::{Host, Url};

use crate::chatgpt_events::{SignedWebhook, MAX_CHALLENGE_RESPONSE_BYTES};

const MAX_URL_BYTES: usize = 8192;
const MAX_DNS_ANSWERS: usize = 32;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
static DNS_SLOTS: Semaphore = Semaphore::const_new(8);

/// Reports a redacted transport category, never a URL, address, header or body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookEgressError {
    InvalidLimits,
    InvalidCallback,
    NonPublicAddress,
    DnsFailed,
    TooManyAddresses,
    DnsTimeout,
    TotalTimeout(Option<StatusCode>),
    TransportFailed,
    TransportTimeout,
    RedirectRejected(StatusCode),
    ResponseTooLarge(StatusCode),
    EncodedResponse(StatusCode),
    ResponseReadFailed(StatusCode),
    ResponseReadTimeout(StatusCode),
}

impl fmt::Display for WebhookEgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "invalid webhook transport limits",
            Self::InvalidCallback => "invalid webhook HTTPS callback",
            Self::NonPublicAddress => "webhook destination is not public",
            Self::DnsFailed => "webhook DNS resolution failed",
            Self::TooManyAddresses => "webhook DNS answer limit exceeded",
            Self::DnsTimeout => "webhook DNS resolution timed out",
            Self::TotalTimeout(_) => "webhook attempt deadline exceeded",
            Self::TransportFailed => "webhook HTTPS transport failed",
            Self::TransportTimeout => "webhook HTTPS operation timed out",
            Self::RedirectRejected(_) => "webhook redirects are forbidden",
            Self::ResponseTooLarge(_) => "webhook response exceeds byte limit",
            Self::EncodedResponse(_) => "webhook encoded responses are forbidden",
            Self::ResponseReadFailed(_) => "webhook response read failed",
            Self::ResponseReadTimeout(_) => "webhook response read timed out",
        })
    }
}

impl WebhookEgressError {
    /// Returns a status already received before a response failure or deadline.
    ///
    /// Preserve this when applying application-owned retry policy. For example,
    /// a terminal 410/413 must not be lost because its error page was oversized.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::TotalTimeout(status) => *status,
            Self::RedirectRejected(status)
            | Self::ResponseTooLarge(status)
            | Self::EncodedResponse(status)
            | Self::ResponseReadFailed(status)
            | Self::ResponseReadTimeout(status) => Some(*status),
            _ => None,
        }
    }
}

impl std::error::Error for WebhookEgressError {}

/// Sets finite per-attempt budgets; defaults also fit challenge echo responses.
#[derive(Clone, Copy, Debug)]
pub struct WebhookEgressLimits {
    pub dns_timeout: Duration,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub total_timeout: Duration,
    pub response_bytes: usize,
}

impl Default for WebhookEgressLimits {
    fn default() -> Self {
        Self {
            dns_timeout: Duration::from_secs(3),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(3),
            total_timeout: Duration::from_secs(15),
            response_bytes: MAX_CHALLENGE_RESPONSE_BYTES,
        }
    }
}

/// Retains only limits, never a pooled client, callback, headers or credentials.
#[derive(Clone, Copy, Debug, Default)]
pub struct WebhookEgress {
    limits: WebhookEgressLimits,
}

impl WebhookEgress {
    /// Constructs a sender with positive finite durations and a bounded response.
    ///
    /// # Errors
    /// Rejects zero durations, durations over 60 seconds, phase budgets longer
    /// than the total, and response limits outside 1..=65536 bytes.
    ///
    /// ```
    /// use mcp_toolkit_http::webhook_egress::{WebhookEgress, WebhookEgressLimits};
    /// let sender = WebhookEgress::new(WebhookEgressLimits::default())?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(limits: WebhookEgressLimits) -> Result<Self, WebhookEgressError> {
        for duration in [
            limits.dns_timeout,
            limits.connect_timeout,
            limits.read_timeout,
            limits.total_timeout,
        ] {
            if duration.is_zero()
                || duration > Duration::from_secs(60)
                || duration > limits.total_timeout
            {
                return Err(WebhookEgressError::InvalidLimits);
            }
        }
        if limits.response_bytes == 0 || limits.response_bytes > MAX_RESPONSE_BYTES {
            return Err(WebhookEgressError::InvalidLimits);
        }
        Ok(Self { limits })
    }

    /// Sends exactly one signed POST and reads a bounded, uncompressed response.
    ///
    /// # Errors
    /// Rejects malformed/ambiguous URLs, non-public or excessive DNS answers,
    /// redirects, encoded or oversized responses, and DNS/TLS/network failures
    /// or deadlines. Non-redirect HTTP error statuses are returned to the caller.
    ///
    /// # Security
    /// Authorize the exact callback, principal, generation and event immediately
    /// before calling. Supply fresh signing time. Dropping this future abandons
    /// request/response handling; queued or in-flight bytes may still arrive.
    /// No automatic retry or background dispatch is started. The caller needs a
    /// Tokio runtime with I/O and time enabled. Do not log accessor results.
    ///
    /// # Panics
    /// Panics if polled without the required Tokio runtime/I/O/time drivers.
    ///
    /// ```no_run
    /// use mcp_toolkit_http::{chatgpt_events::SignedWebhook, webhook_egress::*};
    /// async fn authorized_attempt(callback: &str, signed: &SignedWebhook<'_>)
    ///     -> Result<WebhookResponse, WebhookEgressError>
    /// {
    ///     WebhookEgress::default().send(callback, signed).await
    /// }
    /// ```
    pub async fn send(
        &self,
        callback: &str,
        request: &SignedWebhook<'_>,
    ) -> Result<WebhookResponse, WebhookEgressError> {
        self.send_with_resolver(callback, request, resolve_system)
            .await
    }

    async fn send_with_resolver<F, Fut>(
        &self,
        callback: &str,
        request: &SignedWebhook<'_>,
        resolve: F,
    ) -> Result<WebhookResponse, WebhookEgressError>
    where
        F: FnOnce(String, u16) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<SocketAddr>, WebhookEgressError>>,
    {
        let mut received_status = None;
        timeout(self.limits.total_timeout, async {
            let target = Callback::parse(callback)?;
            let addresses = if let Some(ip) = target.literal {
                PublicAddresses::new([SocketAddr::new(ip, target.port)])?
            } else {
                let answers = timeout(
                    self.limits.dns_timeout,
                    resolve(target.hostname.clone(), target.port),
                )
                .await
                .map_err(|_| WebhookEgressError::DnsTimeout)??;
                PublicAddresses::new(answers)?
            };
            let client = client_builder(&target, addresses, self.limits)?
                .build()
                .map_err(transport_error)?;
            send_once(
                client,
                target.url,
                request,
                self.limits.response_bytes,
                &mut received_status,
            )
            .await
        })
        .await
        .map_err(|_| WebhookEgressError::TotalTimeout(received_status))?
    }
}

/// Holds bounded response bytes; consuming them does not authorize activation.
pub struct WebhookResponse {
    status: StatusCode,
    body: Vec<u8>,
}

impl WebhookResponse {
    /// Returns the HTTP status without interpreting application success.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Borrows sensitive response bytes, for example for `PendingChallenge::verify`.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for WebhookResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

struct Callback {
    url: Url,
    hostname: String,
    port: u16,
    literal: Option<IpAddr>,
}

impl Callback {
    fn parse(input: &str) -> Result<Self, WebhookEgressError> {
        let invalid = WebhookEgressError::InvalidCallback;
        if input.len() > MAX_URL_BYTES
            || !input.starts_with("https://")
            || input.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b'\\')
            || input.contains('#')
        {
            return Err(invalid);
        }
        let authority = input[8..].split(['/', '?']).next().ok_or(invalid)?;
        if authority.is_empty() || authority.contains(['@', '%']) || !authority.is_ascii() {
            return Err(invalid);
        }
        let url = Url::parse(input).map_err(|_| invalid)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid);
        }
        let port = url.port_or_known_default().ok_or(invalid)?;
        if port == 0 {
            return Err(invalid);
        }
        let raw_host = if authority.starts_with('[') {
            let end = authority.find(']').ok_or(invalid)?;
            &authority[..=end]
        } else {
            authority.split(':').next().ok_or(invalid)?
        };
        // Reject parser reinterpretations (numeric shorthand, escaped hosts,
        // IDNA, trailing dots and noncanonical ports), rather than signing up
        // one host spelling and connecting with another.
        let (hostname, literal) = match url.host().ok_or(invalid)? {
            Host::Domain(host) => {
                if host != raw_host
                    || host.len() > 253
                    || !host.contains('.')
                    || host.split('.').any(|label| {
                        label.is_empty()
                            || label.len() > 63
                            || label.starts_with('-')
                            || label.ends_with('-')
                            || !label
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    })
                {
                    return Err(invalid);
                }
                (host.to_owned(), None)
            }
            Host::Ipv4(ip) => {
                if raw_host != ip.to_string() {
                    return Err(invalid);
                }
                (ip.to_string(), Some(IpAddr::V4(ip)))
            }
            Host::Ipv6(ip) => {
                if raw_host != format!("[{ip}]") {
                    return Err(invalid);
                }
                (ip.to_string(), Some(IpAddr::V6(ip)))
            }
        };
        if authority != raw_host && authority != format!("{raw_host}:{port}") {
            return Err(invalid);
        }
        if literal.is_some_and(|ip| !public_address(ip)) {
            return Err(WebhookEgressError::NonPublicAddress);
        }
        Ok(Self {
            url,
            hostname,
            port,
            literal,
        })
    }
}

async fn resolve_system(host: String, port: u16) -> Result<Vec<SocketAddr>, WebhookEgressError> {
    resolve_blocking(move || {
        let addresses = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|_| WebhookEgressError::DnsFailed)?;
        Ok(addresses.take(MAX_DNS_ANSWERS + 1).collect())
    })
    .await
}

async fn resolve_blocking<T: Send + 'static>(
    lookup: impl FnOnce() -> Result<T, WebhookEgressError> + Send + 'static,
) -> Result<T, WebhookEgressError> {
    let permit = DNS_SLOTS
        .acquire()
        .await
        .map_err(|_| WebhookEgressError::DnsFailed)?;
    tokio::task::spawn_blocking(move || {
        // Hold admission even after the awaiting future is cancelled.
        let _permit = permit;
        lookup()
    })
    .await
    .map_err(|_| WebhookEgressError::DnsFailed)?
}

// This sealed type is constructed only by validating the complete bounded DNS
// answer set. Tests may construct it directly to exercise loopback TLS without
// creating any production private-address bypass.
struct PublicAddresses(Vec<SocketAddr>);

impl PublicAddresses {
    fn new(addresses: impl IntoIterator<Item = SocketAddr>) -> Result<Self, WebhookEgressError> {
        let mut validated = Vec::new();
        for address in addresses {
            if validated.len() == MAX_DNS_ANSWERS {
                return Err(WebhookEgressError::TooManyAddresses);
            }
            if !public_address(address.ip()) || address.port() == 0 {
                return Err(WebhookEgressError::NonPublicAddress);
            }
            validated.push(address);
        }
        if validated.is_empty() {
            return Err(WebhookEgressError::DnsFailed);
        }
        Ok(Self(validated))
    }
}

struct PinnedResolver {
    hostname: String,
    addresses: PublicAddresses,
}

impl Resolve for PinnedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let result: Result<Addrs, Box<dyn std::error::Error + Send + Sync>> =
            if name.as_str() == self.hostname {
                Ok(Box::new(self.addresses.0.clone().into_iter()))
            } else {
                Err(Box::new(WebhookEgressError::DnsFailed))
            };
        Box::pin(std::future::ready(result))
    }
}

fn client_builder(
    target: &Callback,
    addresses: PublicAddresses,
    limits: WebhookEgressLimits,
) -> Result<reqwest::ClientBuilder, WebhookEgressError> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| WebhookEgressError::TransportFailed)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(reqwest::Client::builder()
        .https_only(true)
        .tls_backend_preconfigured(tls)
        .tls_sslkeylogfile(false)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .http1_only()
        .http1_max_headers(32)
        .pool_max_idle_per_host(0)
        .connect_timeout(limits.connect_timeout)
        .read_timeout(limits.read_timeout)
        .timeout(limits.total_timeout)
        .dns_resolver(Arc::new(PinnedResolver {
            hostname: target.hostname.clone(),
            addresses,
        })))
}

async fn send_once(
    client: reqwest::Client,
    url: Url,
    request: &SignedWebhook<'_>,
    response_bytes: usize,
    received_status: &mut Option<StatusCode>,
) -> Result<WebhookResponse, WebhookEgressError> {
    let mut response = client
        .post(url)
        .headers(request.headers().clone())
        .header(http::header::ACCEPT_ENCODING, "identity")
        .header(http::header::CONNECTION, "close")
        .body(request.body().to_vec())
        .send()
        .await
        .map_err(transport_error)?;
    let status = response.status();
    *received_status = Some(status);
    if status.is_redirection() {
        return Err(WebhookEgressError::RedirectRejected(status));
    }
    if response
        .headers()
        .contains_key(http::header::CONTENT_ENCODING)
    {
        return Err(WebhookEgressError::EncodedResponse(status));
    }
    if response
        .content_length()
        .is_some_and(|n| n > response_bytes as u64)
    {
        return Err(WebhookEgressError::ResponseTooLarge(status));
    }
    let mut body = Vec::new();
    loop {
        let next = response.chunk().await.map_err(|error| {
            if error.is_timeout() {
                WebhookEgressError::ResponseReadTimeout(status)
            } else {
                WebhookEgressError::ResponseReadFailed(status)
            }
        })?;
        let Some(chunk) = next else {
            break;
        };
        if chunk.len() > response_bytes - body.len() {
            return Err(WebhookEgressError::ResponseTooLarge(status));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(WebhookResponse { status, body })
}

fn transport_error(error: reqwest::Error) -> WebhookEgressError {
    if error.is_timeout() {
        WebhookEgressError::TransportTimeout
    } else {
        WebhookEgressError::TransportFailed
    }
}

// Conservative globally routable unicast profile. Special-use IPv4 blocks and
// IPv6 outside 2000::/3 are denied; deny transitional/documentation/protocol
// ranges within it too. Registry updates require review, not an allow override.
fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => public_v6(ip),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !matches!(a, 0 | 10 | 127 | 224..=255)
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 169 && b == 254)
        && !(a == 172 && (16..=31).contains(&b))
        && !(a == 192 && b == 0 && (c == 0 || c == 2))
        && !(a == 192 && b == 88 && c == 99)
        && !(a == 192 && b == 168)
        && !(a == 198 && (b == 18 || b == 19))
        && !(a == 198 && b == 51 && c == 100)
        && !(a == 203 && b == 0 && c == 113)
        // Azure's platform virtual IP is globally numbered but is not a public
        // callback destination. Other mainstream metadata endpoints are already
        // denied by the special-use ranges above.
        && ip != Ipv4Addr::new(168, 63, 129, 16)
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    (0x2000..=0x3fff).contains(&s[0])
        && !(s[0] == 0x2001 && s[1] <= 0x01ff)
        && !(s[0] == 0x2001 && s[1] == 0x0db8)
        && s[0] != 0x2002
        && !(s[0] == 0x3fff && s[1] <= 0x0fff)
}

#[cfg(test)]
mod tests;
