//! Verify authenticated private mailbox traffic over HTTPS relay forwarding with no direct path.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::{RelayMode, presets};
use iroh::{Endpoint, EndpointAddr, RelayUrl, SecretKey};
use iroh_relay::server::{CertConfig, RelayConfig, Server, ServerConfig, TlsConfig};
use iroh_relay::tls::{CaTlsConfig, default_provider};
use rustls::pki_types::PrivatePkcs8KeyDer;

use crate::mailbox::{ALPN, AccessKey, Client, ReadResult, WriteResult};
use crate::mailbox_server::{Mailbox, serve_connection};
use crate::slot_store::SlotStore;
use crate::slot_wire::slot_address;

#[tokio::test]
#[ignore = "opens a disposable HTTPS relay and local TCP sockets"]
async fn mailbox_works_with_only_an_authenticated_https_relay_path() -> Result<()> {
    let loopback = (Ipv4Addr::LOCALHOST, 0);
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![Ipv4Addr::LOCALHOST.to_string()])?;
    let certificate = cert.der().clone();
    let server_config = rustls::ServerConfig::builder_with_provider(default_provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )?;
    let mut config = RelayConfig::new(loopback);
    config.tls = Some(TlsConfig::new(
        loopback,
        CertConfig::Manual { server_config },
    ));
    let mut server_config = ServerConfig::default();
    server_config.relay = Some(config);
    let relay = Server::spawn(server_config).await?;
    let url: RelayUrl = format!(
        "https://{}",
        relay.https_addr().context("missing HTTPS listener")?
    )
    .parse()?;

    let bind = || {
        Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .relay_mode(RelayMode::custom([url.clone()]))
            .ca_tls_config(CaTlsConfig::custom_roots([certificate.clone()]))
            .alpns(vec![ALPN.to_vec()])
            .bind()
    };
    let (destination, source) = tokio::try_join!(bind(), bind())?;
    assert!(destination.bound_sockets().is_empty());
    assert!(source.bound_sockets().is_empty());

    let dir = tempfile::tempdir()?;
    let store = SlotStore::initialize(dir.path())?;
    let incarnation = store.incarnation();
    let access = AccessKey::random()?;
    let mailbox = Arc::new(Mailbox::new(
        store,
        *destination.id().as_bytes(),
        [access.verifier()],
    ));
    let endpoint = destination.clone();
    let serving = tokio::spawn(async move {
        let incoming = endpoint.accept().await.context("mailbox endpoint closed")?;
        serve_connection(mailbox, incoming.await?).await;
        Ok::<_, anyhow::Error>(())
    });

    tokio::time::timeout(Duration::from_secs(20), async {
        destination.online().await;
        let addr = EndpointAddr::new(destination.id()).with_relay_url(url);
        let client = Client::connect(&source, addr, &access).await?;
        assert_eq!(client.incarnation().await?, incarnation);
        let key = SecretKey::generate();
        let payload = b"opaque membership ciphertext";
        assert_eq!(
            client.write(&incarnation, &key, payload).await?,
            WriteResult::Created
        );
        let slot = slot_address(key.public().as_bytes());
        assert_eq!(
            client.read(&incarnation, &slot).await?,
            ReadResult::Present(payload.to_vec())
        );
        Ok::<_, anyhow::Error>(())
    })
    .await??;

    source.close().await;
    destination.close().await;
    serving.await??;
    relay.shutdown().await?;
    Ok(())
}
