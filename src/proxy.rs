use async_trait::async_trait;
use tracing::{info,debug};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;
use pingora::listeners::TlsAccept;
use pingora::server::Server;
use pingora::server::configuration::ServerConf;
use std::ffi::OsStr;
use tokio::net::lookup_host;

use crate::ca::{self, get_certificate_authority};
use crate::commands::StartArgs;

// The host header is in different places for HTTPS vs HTTP, see: 
// https://github.com/cloudflare/pingora/issues/125#issuecomment-1987052630
fn get_host(session: &mut Session) -> String {
    if let Some(host) = session.get_header("host") {
        if let Ok(host) = host.to_str() {
            info!("Using host header as sni: {}", host);
            return host.to_string();
        }
    }

    if let Some(host) = session.req_header().uri.host() {
        info!("Using host header as sni: {}", host);
        return host.to_string();
    }

    info!("Using default BLANK SNI value");
    "".to_string()
}

#[derive(Debug)]
pub struct Mitm{
    pub name: String,
    pub verify_cert: bool,
    pub verify_hostname: bool,
    pub upstream: Option<std::net::SocketAddrV4>, 
    pub upstream_sni: Option<String>,
    pub upstream_tls: bool,
    pub stub: bool,
}

#[async_trait]
impl ProxyHttp for Mitm {
    // Haven't found a need yet for a context yet in this program. 
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut ()) -> Result<Box<HttpPeer>> {
        info!("{}: Request: {:?}", self.name, session.request_summary());

        // Note: setting the SNI to blank apparently causes SNI checks to be ignored
        // for the upstream certificate.
        // (but not when using pingora feature "rustls", which throws an error)

        //**Accessing the SNI in this method requires the fork outlined in the Cargo.toml**
        // What's used for the SNI is:
        // 1. Did the user supply a custom sni
        // 2. If not we'll try to use the SNI of the downstream session
        // 3. If that doesn't exist we'll attempt to use the host header
        // 4. If that doesn't exist we'll just use an empty string 
        // 
        // Probably should consider sending the IP address as the SNI on upstream requests. 
        // Attempting to use the host header first is specifically to address the Wireshark 
        // mode where the request is: HTTPS <--> HTTP <--> HTTPS. 

        let sni: &str = match &self.upstream_sni { 
            Some(custom_sni) => { // (1)
                info!("Using user specified sni: {}", custom_sni);
                custom_sni
            }
            None => { 
                let ssl_digest = session.downstream_session.digest().unwrap().ssl_digest.clone();

                // The SSL_digest above will not exist when the downstream is unencrypted 
                let sni = match ssl_digest {
                    Some(arc) => arc.as_ref().sni.clone(),
                    None => None,
                };

                match sni { 
                    Some(sni) => { // (2)
                        info!("Using downstream sni: {}", sni);
                        &sni.clone()
                    }
                    None => { 
                        let host = get_host(session); // (3) / (4)
                        &host.clone()
                    }
                }
            }
        };

        // If the upstream peer is not not specified, we'll do a dynamic (DNS) lookup 
        // using the first returned address. Otherwise we'll use the upstream provided. 
        let mut peer;
        if self.upstream.is_none() {
            let addr_str = format!("{}:443", sni);
            let mut addrs = lookup_host(addr_str).await.unwrap();
            let socket_addr = addrs.next().unwrap();
            peer = Box::new(HttpPeer::new(socket_addr.to_string(), self.upstream_tls, sni.to_string()));
        } else {
            peer = Box::new(HttpPeer::new(self.upstream.as_ref().unwrap(), self.upstream_tls, sni.to_string()));
        }
        peer.options.verify_cert = self.verify_cert;
        peer.options.verify_hostname = self.verify_hostname;
        
        Ok(peer)
    }

    // Handles all responses in Stub mode, or when user requests /cdn-cgi
    async fn request_filter(&self, session: &mut Session, _ctx: &mut ()) -> Result<bool> {
        let path = session.req_header().uri.path();

        if self.stub || path.starts_with("/cdn-cgi") {
            let mut body = String::from("Welcome to the MITM proxy\n\n");
            body.push_str(session.request_summary().as_str());
            body.push_str(&format!("\nMethod: {}\n", session.req_header().method));
            body.push_str(&format!("URI: {}\n", session.req_header().uri));
            body.push_str(&format!("HTTP Version: {:?}\n", session.req_header().version));
            body.push_str(&format!("Remote Address: {:?}\n", session.client_addr()));
            // TLS info, if available
            if let Some(digest) = session.downstream_session.digest() {
                if let Some(ssl) = digest.ssl_digest.as_ref() {
                    if let Some(sni) = &ssl.sni {
                        body.push_str(&format!("TLS SNI: {}\n", sni));
                    }
                    body.push_str(&format!("TLS Version: {}\n", &ssl.version));
                    body.push_str(&format!("TLS Cipher: {}\n", &ssl.cipher));                   
                }
            }
            body.push_str("\n\nRequest Headers:\n");
            for (name, value) in session.req_header().headers.iter() {
                body.push_str(&format!("{}: {:?}\n", name, value));
            }
            
            session.respond_error_with_body(200, body.into()).await.unwrap();
            Ok(true)
            // return Err(Error::new(ErrorType::InternalError));
        } else {
            Ok(false)
        }
    }

}

pub struct MyCertProvider{
    cert_cache: ca::CertCache,
    ca_cert: X509,
    ca_pkey: PKey<Private>,
}

impl MyCertProvider {
    pub fn new() -> Self {
        // let mitm_dir = ca::get_mitm_directory();
        let cert_cache = ca::CertCache::new();
        let (ca_cert, ca_pkey) = get_certificate_authority();
        let mut cert_provider =  MyCertProvider { cert_cache, ca_cert, ca_pkey };
        cert_provider.fill_cache();
        cert_provider        
    }

    // Security Note:
    // The CA certifcate and private key is initialized into the cache, indexed as `ca`
    pub async fn get_leaf_cert(&self, sni: &str) -> (X509, PKey<Private>) {
        // Try to get from cache first
        if let Some(entry) = self.cert_cache.get(sni) {
            // Clone to return owned values
            info!("Cert cache hit: {}", sni);
            debug!{"Cert: {:?}", entry.0.clone()};
            return (entry.0.clone(), entry.1.clone());
        }

        // Otherwise, generate and insert into cache
        info!("Generating leaf certificate for: {}", sni);

        let cert = ca::get_leaf_cert(&self.ca_cert, &self.ca_pkey, sni, true).await;
        // info!{"{:?}", cert.0.clone()};
        self.cert_cache.insert(sni.to_string(), (cert.0.clone(), cert.1.clone()));
        cert
    }

    fn fill_cache(&mut self) {
        let mitm_dir = ca::get_mitm_directory();

        if let Ok(entries) = std::fs::read_dir(&mitm_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                match path.extension() {
                    Some(ext) if ext == OsStr::new("crt") => {}
                    _ => continue,
                };

                let stem = match path.file_stem().and_then(|s| s.to_str()) {
                    Some(stem) => stem,
                    None => continue,
                };

                // Read cert
                let crt_data = match std::fs::read(&path) {
                    Ok(data) => data,
                    Err(e) => {
                        debug!("Could not read cert file {:?}: {}", path, e);
                        continue;
                    }
                };
                let x509 = match X509::from_pem(&crt_data) {
                    Ok(cert) => cert,
                    Err(e) => {
                        debug!("Could not parse cert {:?}: {}", path, e);
                        continue;
                    }
                };

                // Read corresponding key
                let mut key_path = path.clone();
                key_path.set_extension("key");
                let key_data = match std::fs::read(&key_path) {
                    Ok(data) => data,
                    Err(e) => {
                        debug!("Could not read key file {:?}: {}", key_path, e);
                        continue;
                    }
                };
                let pkey = match PKey::private_key_from_pem(&key_data) {
                    Ok(key) => key,
                    Err(e) => {
                        debug!("Could not parse key {:?}: {}", key_path, e);
                        continue;
                    }
                };

                debug!("Filling cert_cache with entry: {}", stem);
                self.cert_cache.insert(stem.to_string(), (x509, pkey));
            }
        }
    }
}

#[async_trait]
impl TlsAccept for MyCertProvider {
    async fn certificate_callback(&self, ssl: &mut pingora::protocols::tls::TlsRef) -> () {

        let sni = ssl.servername(openssl::ssl::NameType::HOST_NAME)
            .unwrap_or_default()
            .to_string();
        debug!("Certificate Callback called for SNI: {}", sni);

        // let leaf = ca::get_leaf_cert_openssl(&sni).await;
        let leaf = &self.get_leaf_cert(&sni).await;
        ssl.set_certificate(&leaf.0).unwrap();        
        ssl.set_private_key(&leaf.1).unwrap();
    }
}

impl From<StartArgs> for Server {
    fn from(start_args: StartArgs) -> Self {
        let ca_file: Option<String> = start_args.ca_file.as_ref().map(|p| p.to_string_lossy().into());

        let config = ServerConf {
            ca_file,
            upstream_debug_ssl_keylog: start_args.upstream_ssl_keys,
            ..Default::default()
        };

        debug!("Server created from: {:?}", config);
        let mut server = Server::new_with_opt_and_conf(None, config.validate().unwrap());
        server.bootstrap();
        server
    }
}