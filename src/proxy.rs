use async_trait::async_trait;
use dashmap::DashMap;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;
use pingora::listeners::TlsAccept;
use pingora_openssl::pkey::PKey;
use pingora_openssl::x509::X509;
use std::sync::RwLock;
use log::info;

use crate::ca;

pub struct Mitm;

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
        info!("Connecting using sni: {sni:}");
        let mut peer = Box::new(HttpPeer::new("127.0.0.1:443", true, sni.to_string()));
        // TODO: Turn this into an option supplied from the command line, to enable / disable
        peer.options.verify_cert = false;
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
