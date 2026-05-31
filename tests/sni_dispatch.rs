//! End-to-end test for `DeferredServerConfig`: a Quinn server is configured
//! with two virtual hosts ("host-a.test" and "host-b.test"), each backed by
//! its own self-signed cert. The selector picks the per-host
//! `rustls::ServerConfig` from the parsed SNI. The client connects with a
//! specific SNI and the test succeeds only if the certificate presented by
//! the server matches the SNI it sent (i.e. the selector ran and returned
//! the right config).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use quinn::{ClientConfig, Endpoint, ServerConfig};
use quinn_proto::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig as RustlsServerConfig;

use quinn_deferred_config::{ClientHelloView, DeferredServerConfig};

struct HostCert {
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
}

fn gen_host(name: &'static str) -> HostCert {
    let cert = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    HostCert { cert_der, key_der }
}

fn build_rustls_server(host: &HostCert) -> Arc<RustlsServerConfig> {
    let mut cfg = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![host.cert_der.clone()],
            PrivateKeyDer::Pkcs8(host.key_der.clone_key()),
        )
        .unwrap();
    cfg.alpn_protocols = vec![b"h3".to_vec(), b"hq-29".to_vec()];
    Arc::new(cfg)
}

fn build_client_endpoint(roots: &[&CertificateDer<'static>]) -> Endpoint {
    let mut store = rustls::RootCertStore::empty();
    for root in roots {
        store.add((*root).clone()).unwrap();
    }
    let crypto = rustls::ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();
    let mut crypto = crypto;
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let client_cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
    let mut ep = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    ep.set_default_client_config(client_cfg);
    ep
}

async fn run_dispatch(target_sni: &'static str) -> Vec<u8> {
    let host_a = gen_host("host-a.test");
    let host_b = gen_host("host-b.test");

    let cfg_a = build_rustls_server(&host_a);
    let cfg_b = build_rustls_server(&host_b);

    let cfg_a_for_selector = cfg_a.clone();
    let cfg_b_for_selector = cfg_b.clone();
    let selector: quinn_deferred_config::Selector =
        Arc::new(move |hello: &ClientHelloView<'_>| match hello.server_name {
            Some("host-a.test") => cfg_a_for_selector.clone(),
            Some("host-b.test") => cfg_b_for_selector.clone(),
            _ => cfg_a_for_selector.clone(),
        });

    // Default is host-a; the selector must steer to host-b when SNI=host-b.
    let deferred = DeferredServerConfig::new(cfg_a.clone(), selector).unwrap();
    let server_cfg = ServerConfig::with_crypto(Arc::new(deferred));

    let server_ep = Endpoint::server(
        server_cfg,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .unwrap();
    let server_addr = server_ep.local_addr().unwrap();

    let client_ep = build_client_endpoint(&[&host_a.cert_der, &host_b.cert_der]);

    let server_task = tokio::spawn(async move {
        let incoming = server_ep.accept().await.expect("accept");
        let conn = incoming.await.expect("server handshake");
        // Hold the connection open briefly so the client side completes.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(conn);
    });

    let connecting = client_ep.connect(server_addr, target_sni).expect("connect");
    let conn = connecting.await.expect("client handshake");

    // Pull the peer certificate chain that the server presented.
    let peer = conn
        .peer_identity()
        .expect("peer identity present")
        .downcast::<Vec<CertificateDer<'static>>>()
        .expect("peer identity is cert chain");

    let leaf_der = peer[0].to_vec();
    drop(conn);
    drop(client_ep);
    server_task.await.unwrap();
    leaf_der
}

#[tokio::test]
async fn sni_steers_to_selected_config() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let host_b_leaf = run_dispatch("host-b.test").await;

    // Reconstruct what host-b's leaf should look like for comparison.
    // We can't reuse the same gen_host result because it's been moved into
    // run_dispatch, but the test guarantees the selector picked host-b only
    // if the handshake completed at all: with self-signed certs scoped to
    // SNI-specific SANs, the wrong config would have produced a name
    // mismatch on the client side and the handshake would have failed.
    //
    // The leaf bytes are a concrete artefact; we assert they are non-empty
    // and parseable as a DER certificate.
    assert!(!host_b_leaf.is_empty());
    assert!(
        host_b_leaf[0] == 0x30,
        "leaf should start with DER SEQUENCE tag"
    );
}

#[tokio::test]
async fn sni_default_path_also_works() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let host_a_leaf = run_dispatch("host-a.test").await;
    assert!(!host_a_leaf.is_empty());
    assert!(host_a_leaf[0] == 0x30);
}
