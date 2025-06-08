use async_trait::async_trait;
use dashmap::DashMap;
use log::info;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;
use pingora::listeners::TlsAccept;
use pingora_openssl::pkey::PKey;
use pingora_openssl::x509::X509;
use std::sync::RwLock;
use tokio::net::lookup_host;


use crate::ca;

pub struct Mitm{
    pub verify_cert: bool,
    pub dynamic_origin: bool,
}

#[async_trait]
impl ProxyHttp for Mitm {
    /// For this small example, we don't need context storage
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut ()) -> Result<Box<HttpPeer>> {
        // println!("upstream peer is: {self.upstream:?}");

        // Note: setting the SNI to blank apparently causes SNI checks to be ignored
        // for the upstream certificate.
        // (but not when using pingora feature "rustls", which throws an error)

        // Here we're using the SNI from the upstream session
        // **This requires the fork outlined in the Cargo.toml**
        let sni = session
            .downstream_session
            .digest()
            .unwrap()
            .ssl_digest
            .as_ref()
            .unwrap()
            .sni
            .as_ref()
            .unwrap();

        info!("Connecting using sni: {sni}");

        let mut peer;

        if self.dynamic_origin {
            // Do a DNS lookup of the origin given the SNI.
            let addr_str = format!("{}:443", sni);
            let mut addrs = lookup_host(addr_str).await.unwrap();
            // Use the first resolved address
            let socket_addr = addrs.next().unwrap();
            peer = Box::new(HttpPeer::new(socket_addr.to_string(), true, sni.to_string()));
        } else {
            peer = Box::new(HttpPeer::new("127.0.0.1:443", true, sni.to_string()));
        }
        peer.options.verify_cert = self.verify_cert;
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        _upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        // upstream_request
        //     .insert_header("Host", "one.one.one.one")
        //     .unwrap();
        Ok(())
    }
}

type CertCache = DashMap<String, (X509, PKey<openssl::pkey::Private>)>;

pub struct MyCertProvider{
    cert_cache: RwLock<CertCache>,  // Not used, yet... 
}

impl MyCertProvider {
    pub fn new() -> Self {
        // TODO: Can we improve on this RwLock?
        MyCertProvider { cert_cache: RwLock::new(DashMap::new()) }
    }
}

#[async_trait]
impl TlsAccept for MyCertProvider {
    async fn certificate_callback(&self, ssl: &mut pingora::protocols::tls::TlsRef) -> () {

        let sni = ssl.servername(openssl::ssl::NameType::HOST_NAME)
            .unwrap_or_default()
            .to_string();
        info!("Certificate Callback called for SNI: {}", sni);

        let leaf = ca::get_leaf_cert_openssl(&sni).await;
        ssl.set_certificate(&leaf.0).unwrap();        

        // ssl.set_certificate_chain_file("/home/hans/.mitm/chain.pem").unwrap();
        ssl.set_private_key(&leaf.1).unwrap();
        // ssl.set_private_key_file("/home/hans/.mitm/example.sundquist.net.key", openssl::ssl::SslFiletype::PEM).unwrap();
    }
}
