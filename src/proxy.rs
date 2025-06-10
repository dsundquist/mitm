use async_trait::async_trait;
use log::info;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;
use pingora::listeners::TlsAccept;
use pingora_openssl::pkey::{PKey, Private};
use pingora_openssl::x509::X509;
// use pingora::listeners::ALPN;
use tokio::net::lookup_host;


use crate::ca;

pub struct Mitm{
    pub verify_cert: bool,
    pub verify_hostname: bool,
    pub upstream: Option<String>, 
    pub upstream_sni: Option<String>,
    pub upstream_tls: bool,
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
            // TODO: Refactor Me: 
            None => session
                .downstream_session
                .digest()
                .unwrap()
                .ssl_digest
                .as_ref()
                .and_then(|d| d.sni.as_deref())
                .unwrap_or_else(|| {
                    session
                        .get_header("Host")
                        .and_then(|hv| hv.to_str().ok())
                        .unwrap_or("")
                })
        };

        info!("Connecting using sni: {sni}");

        let mut peer;

        if self.upstream.is_none() {
            // Do a DNS lookup of the origin given the SNI.
            let addr_str = format!("{}:443", sni);
            let mut addrs = lookup_host(addr_str).await.unwrap();
            // Use the first resolved address
            let socket_addr = addrs.next().unwrap();
            peer = Box::new(HttpPeer::new(socket_addr.to_string(), self.upstream_tls, sni.to_string()));
        } else {
            peer = Box::new(HttpPeer::new(self.upstream.as_ref().unwrap(), self.upstream_tls, sni.to_string()));
        }
        peer.options.verify_cert = self.verify_cert;
        peer.options.verify_hostname = self.verify_hostname;
        
        // TODO: This causes complete failure, and should be investigated, setting it to H1 for now
        // peer.options.alpn = ALPN::H2; // Force HTTP/2
        // peer.options.alpn = ALPN::H1; // Force HTTP/1
        

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
    pub cert_cache: ca::CertCache,  // Not used, yet... 
}


impl MyCertProvider {
    pub fn new() -> Self {
        // let mitm_dir = ca::get_mitm_directory();
        let mut cert_cache = ca::CertCache::new();
        ca::fill_cache(&mut cert_cache);
        MyCertProvider { cert_cache }
    }

    pub async fn get_leaf_cert(&self, sni: &str) -> (X509, PKey<Private>) {
            // Try to get from cache first
        if let Some(entry) = self.cert_cache.get(sni) {
            // Clone to return owned values
            info!("Cert cache hit: {}", sni);
            info!{"Cert: {:?}", entry.0.clone()};
            return (entry.0.clone(), entry.1.clone());
        }

        // Otherwise, generate and insert into cache
        info!("Generating leaf certificate for: {}", sni);
        let cert = ca::get_leaf_cert_openssl(sni).await;
        // info!{"{:?}", cert.0.clone()};
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
