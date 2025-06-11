use log::info;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedKey, DistinguishedName, DnType, Error, IsCa,
    KeyPair, KeyUsagePurpose,
};
use pingora_openssl::pkey::PKey;
use pingora_openssl::x509::X509;
use std::env;
use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use dashmap::DashMap;

pub type CertCache = DashMap<String, (X509, PKey<openssl::pkey::Private>)>;

/// Get the mitm directory full path ($home/.mitm expanded)
/// TODO:  Likely use a dependency (dirs) to support additional platforms
pub fn get_mitm_directory() -> PathBuf {
    // Get $HOME
    let home_dir = match env::var("HOME") {
        Ok(val) => PathBuf::from(val),
        Err(e) => {
            panic!(
                "Please ensure that the environment variable $HOME, is set. {:?}",
                e
            );
        }
    };

    // Append `.mitm`
    home_dir.join(".mitm")
}

pub fn fill_cache(cert_cache: &mut CertCache) {
    let mitm_dir = get_mitm_directory();

    if let Ok(entries) = std::fs::read_dir(&mitm_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == OsStr::new("crt") {
                        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                            // Read cert
                            let crt_data = std::fs::read(&path).unwrap();
                            let x509 = X509::from_pem(&crt_data).unwrap();

                            // Read corresponding key
                            let mut key_path = path.clone();
                            key_path.set_extension("key");
                            let key_data = std::fs::read(&key_path).unwrap();
                            let pkey = PKey::private_key_from_pem(&key_data).unwrap();

                            cert_cache.insert(stem.to_string(), (x509, pkey));
                        }
                    }
                }
            }
        }
    }
}

/// Ensures that ~/.mitm/ exists, if it doesn't it'll create it
async fn ensure_config_directory_exists() {
    let mitm_dir = get_mitm_directory();

    // Check existence and whether it's a directory
    if !mitm_dir.is_dir() {
        // Create the directory
        info!("Creating mitm config directory at {:?}", mitm_dir);
        tokio::fs::create_dir_all(&mitm_dir).await.unwrap();
    }
}

/// Returns true if and only if both ~/.mitm/ca.crt and ~/.mitm/ca.key exist.
/// This function will panic if one but not the other exists.
fn ca_files_exist() -> bool {
    let mitm_dir = get_mitm_directory();
    let public_cert = mitm_dir.join("ca.crt");
    let private_key = mitm_dir.join("ca.key");

    if public_cert.exists() && private_key.exists() {
        true
    } else if !public_cert.exists() && private_key.exists() {
        panic!("Shouldn't occur: ca.key exists but ca.crt doesn't");
    } else if public_cert.exists() && !private_key.exists() {
        panic!("Shouldn't occur: ca.crt exists but ca.key doesn't");
    } else {
        false
    }
}

/// Get a file from the mitm directory (~/.mitm) as a String
async fn get_from_config_directory(filename: &str) -> String {
    let file_path = get_mitm_directory().join(filename);
    let output = tokio::fs::read_to_string(&file_path)
        .await
        .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", file_path, e));

    info!("Cert for {} loaded: {}", filename, output);
    output
}

/// This will write a file to ~/.mitm/, if it doesn't already exist
async fn write_certificate_to_config_directory(
    file_name: &str,
    contents: String,
    permissions: Option<u32>,
) {
    let cert_path = get_mitm_directory().join(file_name);
    if cert_path.exists() {
        info!("File already exists, not overwriting: {:?}", cert_path);
        return;
    }
    let mut cert_file = tokio::fs::File::create(&cert_path).await.unwrap();

    if let Some(permission) = permissions {
        info!("Setting permissions mode {:o}", permission);
        tokio::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(permission)).await.unwrap();
    }

    info!("Writing file: {:?}", cert_path);
    cert_file.write_all(contents.as_bytes()).await.unwrap();
}

/// Clears the config directory (~/.mitm) of all files 
pub async fn clear_config_directory(save_ca_files: bool) {
    info!("Clearing the config directory");
    let mitm_dir = get_mitm_directory();
    let mut read_dir = tokio::fs::read_dir(mitm_dir).await.unwrap();
    while let Some(entry) = read_dir.next_entry().await.unwrap() {
        let path = entry.path();
        if path.is_file() {
            if save_ca_files && (path.ends_with("ca.crt") || path.ends_with("ca.key")) {
                info!("Skipping CA File: {:?}", path);
            } else {
                tokio::fs::remove_file(&path).await.unwrap();
            }
        } else if path.is_dir() {
            // Optionally clear subdirectories recursively:
            tokio::fs::remove_dir_all(&path).await.unwrap();
        }
    }
}

fn generate_ca_cert(subject_alt_names: impl Into<Vec<String>>) -> Result<CertifiedKey, Error> {
    let key_pair = KeyPair::generate().unwrap();

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "MITM Certificate Authority");

    // TODO:  NEED TO CHECK THESE ARE THE PARAMS THAT ARE ACCEPTABLE FOR A CA
    // Create CertificateParams
    let mut cert_params = CertificateParams::new(subject_alt_names)?;
    cert_params.distinguished_name = distinguished_name;
    cert_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    cert_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::KeyCertSign,
    ];

    let cert = cert_params.self_signed(&key_pair)?;

    Ok(CertifiedKey { 
        cert, 
        key_pair 
    })
}

/// Creates a new Certificate Authority (if one doesn't already exist) in ~/.mitm
/// It creates two files: 
/// * ~/.mitm/ca.key = Private Key (perm: 600) 
/// * ~/.mitm/ca.pem = Public Certificate (perm: 644)
/// 
/// Otherwise, it loads the two files above.  
/// It always returns a CertifiedKey, representing the CA. 
pub async fn get_certificate_authority() -> CertifiedKey {
    ensure_config_directory_exists().await;

    if !ca_files_exist() {
        // Generate, write, and return
        // If the file doesn't already create them, and save thme
        let cert = generate_ca_cert(vec!["test.example.local".to_string()]).unwrap();

        // public cert
        write_certificate_to_config_directory("ca.crt", cert.cert.pem(), Some(0o644)).await;

        // private key
        write_certificate_to_config_directory("ca.key", cert.key_pair.serialize_pem(), Some(0o600)).await;

        CertifiedKey {
            cert: cert.cert,
            key_pair: cert.key_pair,
        }
    } else {
        // Else load the CA, and return it
        // First the key
        let key_string = get_from_config_directory("ca.key").await;
        let key_pair = rcgen::KeyPair::from_pem(&key_string).unwrap();

        

        // Then the certificate
        let cert_string = get_from_config_directory("ca.crt").await;
        let my_cert_params = rcgen::CertificateParams::from_ca_cert_pem(&cert_string).unwrap();

        let cert = my_cert_params.self_signed(&key_pair).unwrap();

        CertifiedKey { 
            cert, 
            key_pair 
        }
    }
}


/// First calls get_certificate_authority(), then generates a leaf certificate (with hostname as CommonName and SAN).
/// Finally it returns a CertifiedKey of the Leaf Certificate. 
pub async fn get_leaf_cert_rcgen(hostname: &str) -> CertifiedKey {
    let ca = get_certificate_authority().await;

    let key_pair = KeyPair::generate().unwrap();

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, hostname);

    // TODO:  NEED TO CHECK THESE ARE THE PARAMS THAT ARE ACCEPTABLE FOR A LEAF CERTIFICATE
    // Create CertificateParams
    let mut cert_params = CertificateParams::new(vec![hostname.to_string()]).unwrap();
    cert_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    cert_params.distinguished_name = distinguished_name;

    // let cert = cert_params.self_signed(&key_pair).unwrap();
    let cert = cert_params
        .signed_by(&key_pair, &ca.cert, &ca.key_pair)
        .unwrap();

    // Write it to the config directory, starting with the public cert
    let file_name = hostname.to_string() + ".crt";
    write_certificate_to_config_directory(&file_name, cert.pem(), Some(0o644)).await;

    // then the private key
    let file_name = hostname.to_string() + ".key";
    write_certificate_to_config_directory(&file_name, key_pair.serialize_pem(), Some(0o600)).await;

    CertifiedKey { cert, key_pair }
}

/// Used instead of generate_leaf_cert, when needing a X509 and PKey for OpenSSL
pub async fn get_leaf_cert_openssl(sni: &str) -> (X509, PKey<openssl::pkey::Private>) {
    // Use OpenSSL APIs to generate a new keypair and a certificate for the given SNI.
    // Return (X509 cert, PKey private_key)
    let my_certified_key = get_leaf_cert_rcgen(sni).await;

    // Get DER-encoded certificate and private key
    let cert_der = my_certified_key.cert.der();
    let key_der = my_certified_key.key_pair.serialized_der();

    // Parse DER into OpenSSL types
    let x509 = X509::from_der(cert_der).unwrap();
    let pkey = PKey::private_key_from_der(key_der).unwrap();

    (x509, pkey)
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn test_generate_ca_cert() {
        // TODO: Create this test!
        unimplemented!();
    }

    #[test]
    fn test_generate_leaf_cert() {
        // TODO: Create this test! 
        // This will panic because it's unimplemented, but shows the pattern:
        // let ca_cert = generate_ca_cert();
        // let (_cert, _key) = generate_leaf_cert(&ca_cert, "example.com");
        // assert!(/* some condition about cert and key */);
        unimplemented!();
    }
}
