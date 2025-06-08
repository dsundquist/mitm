use async_trait::async_trait;
use dashmap::DashMap;
use log::info;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;
use pingora::listeners::TlsAccept;
use pingora_openssl::pkey::{PKey, Private};
use pingora_openssl::x509::X509;
use std::sync::RwLock;
use tokio::net::lookup_host;


use crate::ca;

pub struct Mitm{
    pub verify_cert: bool,
    pub verify_hostname: bool,
    pub upstream: Option<String>, 
    pub upstream_sni: Option<String>,
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

        let sni = match &self.upstream_sni {
            Some(custom_sni) => custom_sni.as_str(),
            None => session
                .downstream_session
                .digest()
                .unwrap()
                .ssl_digest
                .as_ref()
                .and_then(|d| d.sni.as_deref())
                .expect("No SNI found in downstream session"),
        };

        info!("Connecting using sni: {sni}");

        let mut peer;

        if self.upstream.is_none() {
            // Do a DNS lookup of the origin given the SNI.
            let addr_str = format!("{}:443", sni);
            let mut addrs = lookup_host(addr_str).await.unwrap();
            // Use the first resolved address
            let socket_addr = addrs.next().unwrap();
            peer = Box::new(HttpPeer::new(socket_addr.to_string(), true, sni.to_string()));
        } else {
            peer = Box::new(HttpPeer::new(self.upstream.as_ref().unwrap(), true, sni.to_string()));
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

pub struct MyCertProvider{
    cert_cache: ca::CertCache,  // Not used, yet... 
}


impl MyCertProvider {
    pub fn new() -> Self {
        // TODO: Can we improve on this RwLock?
        MyCertProvider { cert_cache: DashMap::new() }
        // WARM the cache here? (from files in ~/.mitm/)
    }

    pub async fn get_leaf_cert(&self, sni: &str) -> (X509, PKey<Private>) {
            // Try to get from cache first
        if let Some(entry) = self.cert_cache.get(sni) {
            // Clone to return owned values
            info!("Cert cache hit: {}", sni);
            return (entry.0.clone(), entry.1.clone());
        }

        // Otherwise, generate and insert into cache
        info!("Generating leaf certificate for: {}", sni);
        let cert = ca::get_leaf_cert_openssl(sni).await;
        self.cert_cache.insert(sni.to_string(), (cert.0.clone(), cert.1.clone()));
        cert
    }
}

#[async_trait]
impl TlsAccept for MyCertProvider {
    async fn certificate_callback(&self, ssl: &mut pingora::protocols::tls::TlsRef) -> () {

        let sni = ssl.servername(openssl::ssl::NameType::HOST_NAME)
            .unwrap_or_default()
            .to_string();
        info!("Certificate Callback called for SNI: {}", sni);

        // let leaf = ca::get_leaf_cert_openssl(&sni).await;
        let leaf = &self.get_leaf_cert(&sni).await;
        ssl.set_certificate(&leaf.0).unwrap();        
        ssl.set_private_key(&leaf.1).unwrap();

    }
}
