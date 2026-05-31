//! Runnable demo: a single Quinn server serves two virtual hosts
//! (`host-a.test`, `host-b.test`) from one UDP port, with the per-host
//! `rustls::ServerConfig` chosen by a SNI-based selector.
//!
//! Two clients connect in sequence, each requesting a different SNI. The
//! server's selector callback is invoked on each connection and the client
//! confirms that the certificate it received matches the host it asked
//! for. If the selector misfired, TLS hostname verification on the client
//! side would have rejected the handshake.
//!
//! Run with:
//!
//!     cargo run --example multi_tenant

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, ServerConfig};
use quinn_proto::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig as RustlsServerConfig;

use quinn_deferred_config::{ClientHelloView, DeferredServerConfig};

struct HostCert {
    name: &'static str,
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
}

fn gen_host(name: &'static str) -> HostCert {
    let cert = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    HostCert {
        name,
        cert_der: CertificateDer::from(cert.cert.der().to_vec()),
        key_der: PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
    }
}

fn build_rustls_server(host: &HostCert) -> Arc<RustlsServerConfig> {
    let mut cfg = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![host.cert_der.clone()],
            PrivateKeyDer::Pkcs8(host.key_der.clone_key()),
        )
        .unwrap();
    cfg.alpn_protocols = vec![b"demo".to_vec()];
    Arc::new(cfg)
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    println!("=== quinn-deferred-config :: multi-tenant demo ===\n");

    // ----- Server: two configured hosts behind one endpoint -----
    let host_a = gen_host("host-a.test");
    let host_b = gen_host("host-b.test");
    println!("Hosts configured on server:");
    println!("  - {} (self-signed cert A)", host_a.name);
    println!("  - {} (self-signed cert B)", host_b.name);
    println!();

    let cfg_a = build_rustls_server(&host_a);
    let cfg_b = build_rustls_server(&host_b);

    // The selector closure is invoked once per accepted connection,
    // after the ClientHello has been parsed but before any policy is
    // committed. It returns the rustls::ServerConfig for that connection.
    let cfg_a_sel = cfg_a.clone();
    let cfg_b_sel = cfg_b.clone();
    let selector: quinn_deferred_config::Selector =
        Arc::new(move |hello: &ClientHelloView<'_>| match hello.server_name {
            Some("host-a.test") => {
                println!("[server] SNI = host-a.test  ->  using cert A");
                cfg_a_sel.clone()
            }
            Some("host-b.test") => {
                println!("[server] SNI = host-b.test  ->  using cert B");
                cfg_b_sel.clone()
            }
            other => {
                println!(
                    "[server] SNI = {:?}  ->  falling back to default (cert A)",
                    other
                );
                cfg_a_sel.clone()
            }
        });

    let deferred = DeferredServerConfig::new(cfg_a.clone(), selector).unwrap();
    let server_cfg = ServerConfig::with_crypto(Arc::new(deferred));
    let server_ep = Endpoint::server(
        server_cfg,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .unwrap();
    let server_addr = server_ep.local_addr().unwrap();
    println!("[server] listening on {server_addr}");
    println!();

    let server_task = tokio::spawn(async move {
        while let Some(incoming) = server_ep.accept().await {
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        println!(
                            "[server] connection established from {}",
                            conn.remote_address()
                        );
                        // Hold open briefly so the client can inspect peer
                        // identity before we drop.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(e) => println!("[server] handshake failed: {e}"),
                }
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    // ----- Client: trusts both certs, will request each in turn -----
    let mut roots = rustls::RootCertStore::empty();
    roots.add(host_a.cert_der.clone()).unwrap();
    roots.add(host_b.cert_der.clone()).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"demo".to_vec()];
    let client_cfg =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    let mut client_ep =
        Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    client_ep.set_default_client_config(client_cfg);

    for (sni, expected) in [
        ("host-a.test", &host_a.cert_der),
        ("host-b.test", &host_b.cert_der),
    ] {
        println!("[client] connecting with SNI = {sni}");
        let conn = client_ep
            .connect(server_addr, sni)
            .expect("connect setup")
            .await
            .expect("handshake");
        let chain = conn
            .peer_identity()
            .expect("peer identity present")
            .downcast::<Vec<CertificateDer<'static>>>()
            .expect("peer identity is cert chain");
        let leaf = &chain[0];
        let label = if sni == "host-a.test" { "A" } else { "B" };
        let result = if leaf.as_ref() == expected.as_ref() {
            "match"
        } else {
            "MISMATCH"
        };
        println!(
            "[client]   server presented cert (leaf len = {} B), expected cert {} -> {}",
            leaf.len(),
            label,
            result
        );
        drop(conn);
        println!();
    }

    client_ep.wait_idle().await;
    server_task.abort();
    let _ = server_task.await;

    println!("=== done ===");
}
