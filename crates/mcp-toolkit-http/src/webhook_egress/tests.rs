//! The public entrypoint always rejects loopback. Only this child test module
//! constructs the private validated-address type for controlled real TLS tests.
//! No network namespace, public listener, external service or TLS bypass is used.

use super::*;
use crate::chatgpt_events::{EventEnvelope, PendingChallenge, PreparedWebhook, WebhookSigner};
use std::io;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";

fn prepared() -> PreparedWebhook {
    let data = serde_json::json!({"text": "snow \u{2603} and \\"});
    PreparedWebhook::event(EventEnvelope {
        event_id: "evt_1",
        name: "item.changed",
        timestamp: time::OffsetDateTime::from_unix_timestamp(100).unwrap(),
        data: data.as_object().unwrap(),
        cursor: Some("cursor-secret"),
    })
    .unwrap()
}

fn signer() -> WebhookSigner {
    WebhookSigner::new("whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", None).unwrap()
}

fn limits() -> WebhookEgressLimits {
    WebhookEgressLimits {
        dns_timeout: Duration::from_millis(200),
        connect_timeout: Duration::from_secs(2),
        read_timeout: Duration::from_secs(2),
        total_timeout: Duration::from_secs(4),
        response_bytes: 1024,
    }
}

#[test]
fn rejects_ambiguous_and_non_https_callbacks() {
    for input in [
        "http://callback.invalid/hook",
        "HTTPS://callback.invalid/hook",
        "https:callback.invalid",
        "https:///callback.invalid",
        "https://",
        "https://user:pass@callback.invalid",
        "https://@callback.invalid",
        "https://callback.invalid#fragment",
        "https://callback.invalid/#",
        "https://callback.invalid\\@public.invalid",
        " https://callback.invalid",
        "https://callback.invalid/\nsecret",
        "https://callback.invalid/\tsecret",
        "https://call%62ack.invalid",
        "https://CALLBACK.invalid",
        "https://callback.invalid.",
        "https://callback..invalid",
        "https://-callback.invalid",
        "https://callback-.invalid",
        "https://localhost",
        "https://\u{00e9}.invalid",
        "https://2130706433",
        "https://0177.0.0.1",
        "https://0x7f000001",
        "https://127.1",
        "https://[fe80::1%25eth0]",
        "https://callback.invalid:0",
        "https://callback.invalid:0443",
        "https://callback.invalid:",
    ] {
        assert!(Callback::parse(input).is_err(), "accepted {input:?}");
    }
    assert!(Callback::parse(&format!(
        "https://callback.invalid/{}",
        "x".repeat(MAX_URL_BYTES)
    ))
    .is_err());
    for input in [
        "https://callback.invalid/path?opaque=x%20y",
        "https://callback.invalid:443/",
        "https://callback.invalid:8443/",
        "https://8.8.8.8/",
        "https://[2606:4700:4700::1111]/",
    ] {
        assert!(Callback::parse(input).is_ok(), "rejected {input}");
    }
}

#[test]
fn classifies_special_use_and_metadata_addresses() {
    for input in [
        "0.0.0.0",
        "0.255.255.255",
        "10.0.0.1",
        "100.64.0.0",
        "100.127.255.255",
        "127.0.0.1",
        "169.254.169.254",
        "169.254.170.2",
        "172.16.0.0",
        "172.31.255.255",
        "192.0.0.9",
        "192.0.0.170",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.1.1",
        "198.18.0.0",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
        "168.63.129.16",
        "::",
        "::1",
        "::127.0.0.1",
        "::ffff:127.0.0.1",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "64:ff9b:1::1",
        "100::1",
        "100:0:0:1::1",
        "2001::1",
        "2001:1::1",
        "2001:20::1",
        "2001:1ff:ffff::1",
        "2001:db8::1",
        "2002:0808:0808::1",
        "3fff::1",
        "3fff:fff:ffff::1",
        "5f00::1",
        "fc00::1",
        "fd00:ec2::254",
        "fe80::1",
        "fec0::1",
        "ff02::1",
    ] {
        assert!(!public_address(input.parse().unwrap()), "accepted {input}");
    }
    for input in [
        "1.1.1.1",
        "8.8.8.8",
        "100.63.255.255",
        "100.128.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.0.1.1",
        "198.20.0.0",
        "223.255.255.255",
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
        "3fff:1000::1",
    ] {
        assert!(public_address(input.parse().unwrap()), "rejected {input}");
    }
}

#[tokio::test]
async fn entrypoint_denies_literals_before_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let request = prepared();
    let signer = signer();
    let signed = request.sign(&signer, "sub_1", 101).unwrap();
    let url = format!(
        "https://127.0.0.1:{}/",
        listener.local_addr().unwrap().port()
    );
    assert_eq!(
        WebhookEgress::default()
            .send(&url, &signed)
            .await
            .unwrap_err(),
        WebhookEgressError::NonPublicAddress
    );
    assert!(timeout(Duration::from_millis(30), listener.accept())
        .await
        .is_err());
}

#[test]
fn dns_answers_fail_closed_as_a_complete_set() {
    let public: SocketAddr = "8.8.8.8:443".parse().unwrap();
    let private: SocketAddr = "127.0.0.1:443".parse().unwrap();
    for answers in [vec![public, private], vec![private, public]] {
        assert!(matches!(
            PublicAddresses::new(answers),
            Err(WebhookEgressError::NonPublicAddress)
        ));
    }
    assert!(matches!(
        PublicAddresses::new([]),
        Err(WebhookEgressError::DnsFailed)
    ));
    assert!(matches!(
        PublicAddresses::new(vec![public; MAX_DNS_ANSWERS + 1]),
        Err(WebhookEgressError::TooManyAddresses)
    ));
    assert!(PublicAddresses::new(vec![public; MAX_DNS_ANSWERS]).is_ok());
    assert!(PublicAddresses::new(["8.8.8.8:0".parse().unwrap()]).is_err());
}

#[tokio::test]
async fn resolver_is_pinned_and_has_no_dns_fallback() {
    let mut simulated_dns = vec!["8.8.8.8:443".parse().unwrap()];
    let pinned = PinnedResolver {
        hostname: "callback.invalid".into(),
        addresses: PublicAddresses::new(simulated_dns.clone()).unwrap(),
    };
    // A later DNS answer cannot change this connection. The next attempt must
    // validate again, and will reject the rebound private answer.
    simulated_dns[0] = "127.0.0.1:443".parse().unwrap();
    for _ in 0..2 {
        let addresses: Vec<_> = pinned
            .resolve("callback.invalid".parse().unwrap())
            .await
            .unwrap()
            .collect();
        assert_eq!(addresses, vec!["8.8.8.8:443".parse().unwrap()]);
    }
    assert!(pinned
        .resolve("different.invalid".parse().unwrap())
        .await
        .is_err());
    assert!(PublicAddresses::new(simulated_dns).is_err());
}

#[test]
fn limits_are_finite_and_errors_are_redacted() {
    for invalid in [
        WebhookEgressLimits {
            response_bytes: 0,
            ..limits()
        },
        WebhookEgressLimits {
            response_bytes: MAX_RESPONSE_BYTES + 1,
            ..limits()
        },
        WebhookEgressLimits {
            dns_timeout: Duration::ZERO,
            ..limits()
        },
        WebhookEgressLimits {
            total_timeout: Duration::from_secs(61),
            ..limits()
        },
        WebhookEgressLimits {
            connect_timeout: Duration::from_secs(5),
            ..limits()
        },
    ] {
        assert_eq!(
            WebhookEgress::new(invalid).unwrap_err(),
            WebhookEgressError::InvalidLimits
        );
    }
    let e = Callback::parse("https://user:secret@callback.invalid/?token=secret")
        .err()
        .unwrap();
    assert!(!format!("{e} {e:?}").contains("secret"));
    assert!(std::error::Error::source(&e).is_none());
    let r = WebhookResponse {
        status: StatusCode::OK,
        body: b"secret".to_vec(),
    };
    assert!(!format!("{r:?}").contains("secret"));
}

struct FixtureDirectory(std::path::PathBuf);

impl FixtureDirectory {
    fn new() -> Self {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).expect("test TLS fixture identifier");
        // Keep fixture paths inside the checkout instead of trusting TMPDIR.
        std::fs::create_dir_all(".tmp").expect("create test TLS root");
        let dir = std::path::PathBuf::from(".tmp").join(format!(
            "mcp-toolkit-egress-tls-{:032x}",
            u128::from_le_bytes(random)
        ));
        std::fs::create_dir(&dir).expect("create exclusive test TLS directory");
        Self(dir)
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    cert: rustls::pki_types::CertificateDer<'static>,
    key: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    fixture_for(false)
}

fn fixture_for(ip: bool) -> &'static Fixture {
    static DNS: OnceLock<Fixture> = OnceLock::new();
    static IP: OnceLock<Fixture> = OnceLock::new();
    let cell = if ip { &IP } else { &DNS };
    cell.get_or_init(|| {
        // Generate ephemeral test-only material at runtime, never commit a key.
        // OpenSSL is provided by the repository's standard Ubuntu CI runner.
        let directory = FixtureDirectory::new();
        let dir = &directory.0;
        let run = |args: &[&str]| {
            assert!(Command::new("openssl")
                .args(args)
                .current_dir(dir)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("OpenSSL is required for the controlled TLS tests")
                .success());
        };
        run(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "key.pem",
            "-out",
            "cert.pem",
            "-days",
            "1",
            "-subj",
            "/CN=callback.invalid",
            "-addext",
            if ip {
                "subjectAltName=DNS:callback.invalid,IP:127.0.0.1"
            } else {
                "subjectAltName=DNS:callback.invalid"
            },
            "-addext",
            "basicConstraints=critical,CA:FALSE",
        ]);
        run(&[
            "x509", "-in", "cert.pem", "-outform", "DER", "-out", "cert.der",
        ]);
        run(&[
            "pkcs8", "-topk8", "-nocrypt", "-in", "key.pem", "-outform", "DER", "-out", "key.der",
        ]);
        let fixture = Fixture {
            cert: std::fs::read(dir.join("cert.der")).unwrap().into(),
            key: std::fs::read(dir.join("key.der")).unwrap(),
        };
        drop(directory);
        fixture
    })
}

fn test_tls() -> rustls::ClientConfig {
    test_tls_for(fixture())
}

fn test_tls_for(fixture: &Fixture) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(fixture.cert.clone()).unwrap();
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

fn acceptor() -> TlsAcceptor {
    acceptor_for(fixture())
}

fn acceptor_for(fixture: &Fixture) -> TlsAcceptor {
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(fixture.key.clone());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![fixture.cert.clone()], key.into())
    .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

#[derive(Debug)]
struct Received {
    headers: String,
    body: Vec<u8>,
    sni: String,
}

enum Step {
    Write(Vec<u8>),
    Pause(Duration),
}

struct Server {
    addr: SocketAddr,
    received: oneshot::Receiver<Received>,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn server(steps: Vec<Step>) -> Server {
    server_using(steps, acceptor()).await
}

async fn server_using(steps: Vec<Step>, acceptor: TlsAcceptor) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, received) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let Ok(mut stream) = acceptor.accept(tcp).await else {
            return;
        };
        let sni = stream
            .get_ref()
            .1
            .server_name()
            .unwrap_or_default()
            .to_owned();
        let mut bytes = Vec::new();
        let end = loop {
            if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            if stream.read_buf(&mut bytes).await.unwrap_or(0) == 0 {
                return;
            }
            assert!(bytes.len() < 300_000);
        };
        let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
        let length: usize = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .unwrap();
        while bytes.len() < end + length {
            if stream.read_buf(&mut bytes).await.unwrap_or(0) == 0 {
                return;
            }
        }
        let _ = tx.send(Received {
            headers,
            body: bytes[end..end + length].to_vec(),
            sni,
        });
        for step in steps {
            match step {
                Step::Write(bytes) => {
                    if stream.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
                Step::Pause(duration) => tokio::time::sleep(duration).await,
            }
        }
        let _ = stream.shutdown().await;
    });
    Server {
        addr,
        received,
        task,
    }
}

fn test_client(
    server: &Server,
    host: &str,
    limits: WebhookEgressLimits,
    trust: bool,
) -> (reqwest::Client, Url) {
    let target = Callback::parse(&format!(
        "https://{host}:{}/hook?token=opaque",
        server.addr.port()
    ))
    .unwrap();
    // Only cfg(test) can manufacture this value with a non-public address.
    let builder = client_builder(&target, PublicAddresses(vec![server.addr]), limits).unwrap();
    let builder = if trust {
        builder.tls_backend_preconfigured(test_tls())
    } else {
        builder
    };
    (builder.build().unwrap(), target.url)
}

async fn perform(
    server: &Server,
    host: &str,
    limits: WebhookEgressLimits,
    trust: bool,
) -> Result<WebhookResponse, WebhookEgressError> {
    let prepared = prepared();
    let signer = signer();
    let signed = prepared.sign(&signer, "sub_1", 101).unwrap();
    let (client, url) = test_client(server, host, limits, trust);
    let mut received_status = None;
    let result = timeout(
        limits.total_timeout,
        send_once(
            client,
            url,
            &signed,
            limits.response_bytes,
            &mut received_status,
        ),
    )
    .await;
    result.map_err(|_| WebhookEgressError::TotalTimeout(received_status))?
}

#[tokio::test]
async fn real_tls_connects_to_pin_preserves_hostname_and_signed_bytes() {
    let mut server = server(vec![Step::Write(OK.to_vec())]).await;
    let result = perform(&server, "callback.invalid", limits(), true)
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::OK);
    assert_eq!(result.body(), b"{}");
    let received = (&mut server.received).await.unwrap();
    assert_eq!(received.sni, "callback.invalid");
    assert!(received
        .headers
        .starts_with("POST /hook?token=opaque HTTP/1.1\r\n"));
    assert!(received.headers.contains(&format!(
        "host: callback.invalid:{}\r\n",
        server.addr.port()
    )));
    assert_eq!(received.body, prepared().body());
    let body = prepared();
    let signer = signer();
    let signed = body.sign(&signer, "sub_1", 101).unwrap();
    for (name, value) in signed.headers() {
        assert!(received
            .headers
            .contains(&format!("{}: {}\r\n", name, value.to_str().unwrap())));
    }
}

#[tokio::test]
async fn tls_rejects_wrong_hostname_and_untrusted_root_before_http() {
    for (host, trust) in [("wrong.invalid", true), ("callback.invalid", false)] {
        let mut server = server(vec![Step::Write(OK.to_vec())]).await;
        assert_eq!(
            perform(&server, host, limits(), trust).await.unwrap_err(),
            WebhookEgressError::TransportFailed
        );
        assert!((&mut server.received).await.is_err());
    }
}

#[tokio::test]
async fn redirects_never_reach_a_second_socket() {
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:{}/secret\r\nContent-Length: 0\r\n\r\n",
        sink.local_addr().unwrap().port()
    );
    let server = server(vec![Step::Write(response.into_bytes())]).await;
    assert_eq!(
        perform(&server, "callback.invalid", limits(), true)
            .await
            .unwrap_err(),
        WebhookEgressError::RedirectRejected(StatusCode::FOUND)
    );
    assert!(timeout(Duration::from_millis(50), sink.accept())
        .await
        .is_err());
}

#[tokio::test]
async fn response_bounds_cover_chunked_length_and_encoding() {
    for (response, expected) in [
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
            Some(WebhookEgressError::ResponseTooLarge(StatusCode::OK)),
        ),
        (
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1\r\nc\r\n0\r\n\r\n",
            Some(WebhookEgressError::ResponseTooLarge(StatusCode::OK)),
        ),
        (
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc",
            Some(WebhookEgressError::ResponseTooLarge(StatusCode::OK)),
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na",
            Some(WebhookEgressError::ResponseReadFailed(StatusCode::OK)),
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nxx",
            Some(WebhookEgressError::EncodedResponse(StatusCode::OK)),
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 2\r\n\r\nab",
            Some(WebhookEgressError::EncodedResponse(StatusCode::OK)),
        ),
        (
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n",
            None,
        ),
        (
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\nab",
            None,
        ),
    ] {
        let server = server(vec![Step::Write(response.as_bytes().to_vec())]).await;
        let result = perform(
            &server,
            "callback.invalid",
            WebhookEgressLimits {
                response_bytes: 2,
                ..limits()
            },
            true,
        )
        .await;
        if let Some(expected) = expected {
            assert_eq!(result.unwrap_err(), expected, "{response}");
        } else {
            assert_eq!(result.unwrap().body(), b"ab", "{response}");
        }
    }
}

#[tokio::test]
async fn response_header_count_and_byte_buffer_are_bounded() {
    for headers in [
        "X-A: a\r\n".repeat(40),
        format!("X-Large: {}\r\n", "a".repeat(512 * 1024)),
    ] {
        let server = server(vec![Step::Write(
            format!("HTTP/1.1 200 OK\r\n{headers}Content-Length: 0\r\n\r\n").into_bytes(),
        )])
        .await;
        assert_eq!(
            perform(&server, "callback.invalid", limits(), true)
                .await
                .unwrap_err(),
            WebhookEgressError::TransportFailed
        );
    }
}

#[tokio::test]
async fn read_idle_and_total_deadlines_stop_slow_peers() {
    let stalled = server(vec![Step::Pause(Duration::from_secs(1))]).await;
    let short = WebhookEgressLimits {
        read_timeout: Duration::from_millis(50),
        ..limits()
    };
    assert_eq!(
        perform(&stalled, "callback.invalid", short, true)
            .await
            .unwrap_err(),
        WebhookEgressError::TransportTimeout
    );
    drop(stalled);
    let mut steps = vec![Step::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n".to_vec(),
    )];
    for _ in 0..20 {
        steps.push(Step::Pause(Duration::from_millis(30)));
        steps.push(Step::Write(b"a".to_vec()));
    }
    let server = server(steps).await;
    let short = WebhookEgressLimits {
        total_timeout: Duration::from_millis(180),
        read_timeout: Duration::from_millis(100),
        ..limits()
    };
    let error = perform(&server, "callback.invalid", short, true)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        WebhookEgressError::TotalTimeout(_) | WebhookEgressError::ResponseReadTimeout(_)
    ));
}

#[tokio::test]
async fn dns_timeout_bounds_admission_and_cancelled_lookup_retains_slot() {
    let held = DNS_SLOTS.acquire_many(8).await.unwrap();
    let body = prepared();
    let signer = signer();
    let signed = body.sign(&signer, "sub_1", 101).unwrap();
    let sender = WebhookEgress::new(WebhookEgressLimits {
        dns_timeout: Duration::from_millis(20),
        ..limits()
    })
    .unwrap();
    assert_eq!(
        sender
            .send("https://callback.invalid/", &signed)
            .await
            .unwrap_err(),
        WebhookEgressError::DnsTimeout
    );
    drop(held);
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let task = tokio::spawn(resolve_blocking(move || {
        let _ = started_tx.send(());
        release_rx.recv().unwrap();
        PublicAddresses::new(["8.8.8.8:443".parse().unwrap()])
    }));
    started_rx.await.unwrap();
    task.abort();
    let _ = task.await;
    assert_eq!(DNS_SLOTS.available_permits(), 7);
    release_tx.send(()).unwrap();
    timeout(Duration::from_secs(2), async {
        while DNS_SLOTS.available_permits() != 8 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancellation_after_send_does_not_retry_and_closes_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (sent_tx, sent_rx) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor().accept(tcp).await.unwrap();
        let mut bytes = [0; 2048];
        assert!(stream.read(&mut bytes).await.unwrap() > 0);
        sent_tx.send(()).unwrap();
        let closed = timeout(Duration::from_secs(2), async {
            loop {
                if stream.read(&mut bytes).await.unwrap_or(0) == 0 {
                    break;
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "cancelled client left socket open");
        assert!(timeout(Duration::from_millis(80), listener.accept())
            .await
            .is_err());
    });
    let body = prepared();
    let signer = signer();
    let signed = body.sign(&signer, "sub_1", 101).unwrap();
    let target = Callback::parse(&format!("https://callback.invalid:{}/", addr.port())).unwrap();
    let client = client_builder(&target, PublicAddresses(vec![addr]), limits())
        .unwrap()
        .tls_backend_preconfigured(test_tls())
        .build()
        .unwrap();
    let mut status = None;
    let mut send = Box::pin(send_once(client, target.url, &signed, 1024, &mut status));
    tokio::select! { _ = sent_rx => {}, result = &mut send => panic!("unexpected completion: {result:?}") }
    drop(send);
    peer.await.unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn proxy_environment_is_ignored_in_an_isolated_process() {
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let url = format!("http://{}", proxy.local_addr().unwrap());
    // Re-execute the kernel-owned running image, not an argv/environment path.
    let output = Command::new("/proc/self/exe")
        .args([
            "--exact",
            "webhook_egress::tests::proxy_environment_child",
            "--nocapture",
        ])
        .env("TOOLKIT_TEST_PROXY_CHILD", "1")
        .env("HTTP_PROXY", &url)
        .env("HTTPS_PROXY", &url)
        .env("ALL_PROXY", &url)
        .env("http_proxy", &url)
        .env("https_proxy", &url)
        .env("all_proxy", &url)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        proxy.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn proxy_environment_child() {
    if std::env::var_os("TOOLKIT_TEST_PROXY_CHILD").is_none() {
        return;
    }
    let server = server(vec![Step::Write(OK.to_vec())]).await;
    assert!(perform(&server, "callback.invalid", limits(), true)
        .await
        .is_ok());
}

#[tokio::test]
async fn signed_challenge_uses_same_transport_and_verifier() {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).expect("test challenge nonce");
    let challenge = PendingChallenge::new("verify_1", nonce, 100, 130).unwrap();
    let signer = signer();
    let signed = challenge.sign(&signer, "sub_1", 101).unwrap();
    let value: serde_json::Value = serde_json::from_slice(signed.body()).unwrap();
    let echo = serde_json::to_vec(&serde_json::json!({"challenge": value["challenge"]})).unwrap();
    let mut response =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", echo.len()).into_bytes();
    response.extend_from_slice(&echo);
    let server = server(vec![Step::Write(response)]).await;
    let (client, url) = test_client(&server, "callback.invalid", limits(), true);
    let mut status = None;
    let response = send_once(
        client,
        url,
        &signed,
        MAX_CHALLENGE_RESPONSE_BYTES,
        &mut status,
    )
    .await
    .unwrap();
    challenge
        .verify(response.status(), response.body(), 102)
        .unwrap();
}

#[tokio::test]
async fn high_level_attempt_re_resolves_and_rejects_private_or_mixed_answers() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let private = listener.local_addr().unwrap();
    let public = SocketAddr::new("8.8.8.8".parse().unwrap(), private.port());
    let body = prepared();
    let signer = signer();
    let signed = body.sign(&signer, "sub_1", 101).unwrap();
    let count = AtomicUsize::new(0);
    let sender = WebhookEgress::new(limits()).unwrap();
    for answers in [vec![private], vec![public, private], vec![private, public]] {
        let result = sender
            .send_with_resolver("https://callback.invalid/", &signed, |host, port| {
                assert_eq!(host, "callback.invalid");
                assert_eq!(port, 443);
                count.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(answers))
            })
            .await;
        assert_eq!(result.unwrap_err(), WebhookEgressError::NonPublicAddress);
    }
    assert_eq!(count.load(Ordering::SeqCst), 3);
    assert!(timeout(Duration::from_millis(50), listener.accept())
        .await
        .is_err());
}

#[tokio::test]
async fn connect_deadline_includes_a_stalled_tls_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 2048];
        assert!(socket.read(&mut bytes).await.unwrap() > 0);
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    let target = Callback::parse(&format!("https://callback.invalid:{}/", addr.port())).unwrap();
    let short = WebhookEgressLimits {
        connect_timeout: Duration::from_millis(50),
        ..limits()
    };
    let client = client_builder(&target, PublicAddresses(vec![addr]), short)
        .unwrap()
        .build()
        .unwrap();
    let body = prepared();
    let signer = signer();
    let signed = body.sign(&signer, "sub_1", 101).unwrap();
    let mut status = None;
    assert_eq!(
        timeout(
            Duration::from_secs(1),
            send_once(client, target.url, &signed, 1024, &mut status)
        )
        .await
        .unwrap()
        .unwrap_err(),
        WebhookEgressError::TransportTimeout
    );
    peer.abort();
}

#[tokio::test]
async fn literal_ip_tls_uses_ip_identity_without_dns_or_sni() {
    struct NeverDns;
    impl Resolve for NeverDns {
        fn resolve(&self, _: Name) -> Resolving {
            panic!("literal IP unexpectedly requested DNS");
        }
    }
    for matching_ip_san in [true, false] {
        let fixture = fixture_for(matching_ip_san);
        let mut server = server_using(vec![Step::Write(OK.to_vec())], acceptor_for(fixture)).await;
        // Only test code constructs this otherwise forbidden loopback target.
        let target = Callback {
            url: Url::parse(&format!("https://{}/hook", server.addr)).unwrap(),
            hostname: "127.0.0.1".into(),
            port: server.addr.port(),
            literal: Some(server.addr.ip()),
        };
        let client = client_builder(&target, PublicAddresses(vec![server.addr]), limits())
            .unwrap()
            .tls_backend_preconfigured(test_tls_for(fixture))
            .dns_resolver(NeverDns)
            .build()
            .unwrap();
        let body = prepared();
        let signer = signer();
        let signed = body.sign(&signer, "sub_1", 101).unwrap();
        let mut status = None;
        let result = send_once(client, target.url, &signed, 1024, &mut status).await;
        if matching_ip_san {
            assert!(result.is_ok());
            let received = (&mut server.received).await.unwrap();
            assert!(received.sni.is_empty());
            assert!(received
                .headers
                .contains(&format!("host: {}\r\n", server.addr)));
        } else {
            assert_eq!(result.unwrap_err(), WebhookEgressError::TransportFailed);
            assert!((&mut server.received).await.is_err());
        }
    }
}

#[tokio::test]
async fn body_failures_preserve_received_status_for_application_retry_policy() {
    for code in [410, 413] {
        let status = StatusCode::from_u16(code).unwrap();
        for suffix in [
            "Content-Length: 9999\r\n\r\n",
            "Content-Encoding: gzip\r\nContent-Length: 2\r\n\r\nxx",
            "Content-Length: 2\r\n\r\na",
        ] {
            let server = server(vec![Step::Write(
                format!("HTTP/1.1 {code} Error\r\n{suffix}").into_bytes(),
            )])
            .await;
            let error = perform(&server, "callback.invalid", limits(), true)
                .await
                .unwrap_err();
            assert_eq!(error.status(), Some(status));
        }
        let server = server(vec![
            Step::Write(format!("HTTP/1.1 {code} Error\r\nContent-Length: 2\r\n\r\n").into_bytes()),
            Step::Pause(Duration::from_secs(1)),
        ])
        .await;
        let short = WebhookEgressLimits {
            read_timeout: Duration::from_millis(40),
            ..limits()
        };
        let error = perform(&server, "callback.invalid", short, true)
            .await
            .unwrap_err();
        assert_eq!(error, WebhookEgressError::ResponseReadTimeout(status));
    }
}

#[tokio::test]
async fn total_deadline_preserves_status_after_headers() {
    let mut steps = vec![Step::Write(
        b"HTTP/1.1 413 Error\r\nContent-Length: 20\r\n\r\n".to_vec(),
    )];
    for _ in 0..20 {
        steps.push(Step::Pause(Duration::from_millis(30)));
        steps.push(Step::Write(b"a".to_vec()));
    }
    let server = server(steps).await;
    let short = WebhookEgressLimits {
        total_timeout: Duration::from_millis(180),
        read_timeout: Duration::from_millis(100),
        ..limits()
    };
    let error = perform(&server, "callback.invalid", short, true)
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(StatusCode::PAYLOAD_TOO_LARGE));
}

#[tokio::test]
async fn every_content_encoding_is_rejected_before_decode() {
    for encoding in ["gzip", "br", "deflate", "zstd", "identity"] {
        let server = server(vec![Step::Write(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: {encoding}\r\nContent-Length: 2\r\n\r\nxx"
            )
            .into_bytes(),
        )])
        .await;
        assert_eq!(
            perform(&server, "callback.invalid", limits(), true)
                .await
                .unwrap_err(),
            WebhookEgressError::EncodedResponse(StatusCode::OK)
        );
    }
}
