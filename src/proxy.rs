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
    pub verify_hostname: bool,
    pub origin: Option<String>, 
}

#[async_trait]
impl ProxyHttp for Mitm {
    // Haven't found a need yet for a context, yet in this program. 
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

        if self.origin.is_none() {
            // Do a DNS lookup of the origin given the SNI.
            let addr_str = format!("{}:443", sni);
            let mut addrs = lookup_host(addr_str).await.unwrap();
            // Use the first resolved address
            let socket_addr = addrs.next().unwrap();
            peer = Box::new(HttpPeer::new(socket_addr.to_string(), true, sni.to_string()));
        } else {
            peer = Box::new(HttpPeer::new(self.origin.as_ref().unwrap(), true, sni.to_string()));
        }
        peer.options.verify_cert = self.verify_cert;
        peer.options.verify_hostname = self.verify_hostname;
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
        ssl.set_private_key(&leaf.1).unwrap();

    }
}
