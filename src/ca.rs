use dashmap::DashMap;
use log::info;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder};
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
use openssl::x509::X509;
use std::io::Write;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

pub type CertCache = DashMap<String, (X509, PKey<openssl::pkey::Private>)>;

/// Get the mitm directory full path ($home/.mitm expanded)
pub fn get_mitm_directory() -> PathBuf {
    // Use dirs crate for cross-platform home directory
    let home_dir = dirs::home_dir().expect("Could not determine home directory for this platform.");
    home_dir.join(".mitm")
}

/// Ensures that ~/.mitm/ exists, if it doesn't it'll create it
fn ensure_config_directory_exists() {
    let mitm_dir = get_mitm_directory();

    // Check existence and whether it's a directory
    if !mitm_dir.is_dir() {
        // Create the directory
        info!("Creating mitm config directory at {:?}", mitm_dir);
        std::fs::create_dir_all(&mitm_dir).unwrap();
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
fn get_from_config_directory(filename: &str) -> Vec<u8> {
    let file_path = get_mitm_directory().join(filename);
    let output = std::fs::read(&file_path)
        .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", file_path, e));

    info!("Cert for {} loaded.", filename);
    output
}

/// This will write a file to ~/.mitm/, if it doesn't already exist
async fn write_certificate_to_config_directory_async(
    file_name: &str,
    contents: Vec<u8>,
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(
                &cert_path,
                std::fs::Permissions::from_mode(permission)
            ).await.unwrap();
        }
        #[cfg(windows)]
        info!("File permissions not set on Windows (not implemented)");
    }

    info!("Writing file: {:?}", cert_path);
    cert_file.write_all(&contents).await.unwrap();
}

fn write_certificate_to_config_directory(
    file_name: &str,
    contents: Vec<u8>,
    permissions: Option<u32>,
) {
    let cert_path = get_mitm_directory().join(file_name);
    if cert_path.exists() {
        info!("File already exists, not overwriting: {:?}", cert_path);
        return;
    }
    let mut cert_file = std::fs::File::create(&cert_path).unwrap();

    if let Some(permission) = permissions {
        info!("Setting permissions mode {:o}", permission);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &cert_path,
                std::fs::Permissions::from_mode(permission)
            ).unwrap();
        }
        #[cfg(windows)]
        info!("File permissions not set on Windows (not implemented)");
    }

    info!("Writing file: {:?}", cert_path);
    cert_file.write_all(&contents).unwrap();
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

fn generate_ca_cert(cn: &str) -> (X509, PKey<Private>) {
    // Generate private key
    let rsa = Rsa::generate(4096).expect("Failed to generate RSA key");
    let pkey = PKey::from_rsa(rsa).expect("Failed to create PKey");

    // Build subject name
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("CN", cn).unwrap();
    let name = name_builder.build();

    // Build certificate
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    // Set validity
    builder.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&openssl::asn1::Asn1Time::days_from_now(3650).unwrap()).unwrap();

    // Set extensions
    let basic_constraints = BasicConstraints::new().ca().build().unwrap();
    builder.append_extension(basic_constraints).unwrap();

    let key_usage = KeyUsage::new()
        .key_cert_sign()
        .crl_sign()
        .build()
        .unwrap();
    builder.append_extension(key_usage).unwrap();

    // Self-sign
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let cert: X509 = builder.build();

    (cert, pkey)
}

/// Creates a new Certificate Authority (if one doesn't already exist) in ~/.mitm
/// It creates two files: 
/// * ~/.mitm/ca.key = Private Key (perm: 600) 
/// * ~/.mitm/ca.pem = Public Certificate (perm: 644)
/// 
/// Otherwise, it loads the two files above.  
/// It always returns a CertifiedKey, representing the CA. 
pub fn get_certificate_authority() -> (X509, PKey<Private>) {
    ensure_config_directory_exists();

    if !ca_files_exist() {
        // Generate, write, and return
        // If the file doesn't already create them, and save thme
        let (cert, pkey) = generate_ca_cert("MITM Certificate Authority");

        // private key
        write_certificate_to_config_directory(
            "ca.key",
            pkey.private_key_to_pem_pkcs8().unwrap(),
            Some(0o600),
        );

        // public cert
        write_certificate_to_config_directory(
            "ca.crt",
            cert.to_pem().unwrap(),
            Some(0o644),
        );

        (cert, pkey)
    } else {
        // Else load the CA, and return it
        // First the key
        let key_string = get_from_config_directory("ca.key");
        let pkey  = PKey::private_key_from_pem(&key_string).expect("Failed to parse CA private key");

        // Then the certificate
        let cert_string = get_from_config_directory("ca.crt");
        let cert = X509::from_pem(&cert_string).expect("Failed to parse CA certificate");

        (cert, pkey)
    }
}

/// First calls get_certificate_authority(), then generates a leaf certificate (with hostname as CommonName and SAN).
/// Finally it returns a CertifiedKey of the Leaf Certificate. 
pub async fn get_leaf_cert(ca_cert: &X509, ca_key: &PKey<Private>, cn: &str, write_to_disk: bool) -> (X509, PKey<Private>) {
    
    // Generate leaf private key
    let rsa = Rsa::generate(2048).expect("Failed to generate RSA key");
    let leaf_pkey = PKey::from_rsa(rsa).expect("Failed to create PKey");

    // Build Common Name for leaf
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("CN", cn).unwrap();
    let name = name_builder.build();

    // Build leaf certificate
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    builder.set_pubkey(&leaf_pkey).unwrap();
    

    // Set validity
    builder.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&openssl::asn1::Asn1Time::days_from_now(365).unwrap()).unwrap();

    // Set extensions (no CA, only digitalSignature and keyEncipherment)
    let basic_constraints = BasicConstraints::new().critical().build().unwrap();
    builder.append_extension(basic_constraints).unwrap();

    // Add the Subject Alternative Name (SAN)
    let san = SubjectAlternativeName::new()
        .dns(cn)
        .build(&builder.x509v3_context(Some(ca_cert), None))
        .unwrap();
    builder.append_extension(san).unwrap();

    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    builder.append_extension(key_usage).unwrap();

    // Sign with CA key
    builder.sign(&ca_key, MessageDigest::sha256()).unwrap();

    let cert = builder.build();

    // Write it to the config directory, starting with the private key
    if write_to_disk {
        let file_name = cn.to_string() + ".key";
        write_certificate_to_config_directory_async(
            &file_name,
            leaf_pkey.private_key_to_pem_pkcs8().unwrap(),
            Some(0o600)
        ).await;

        // then the public cert
        let file_name = cn.to_string() + ".crt";
        write_certificate_to_config_directory_async(
            &file_name,
            cert.to_pem().unwrap(),
            Some(0o644)).await;
    }
    
    (cert, leaf_pkey)

}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::nid::Nid;

    #[test]
    fn test_generate_ca_cert() {
        // Generate a CA cert and key
        let (cert, key) = generate_ca_cert("test.example.local");

        // Check that the certificate and key are not empty
        let cert_pem = cert.to_pem().expect("Failed to encode cert to PEM");
        let key_pem = key.private_key_to_pem_pkcs8().expect("Failed to encode key to PEM");
        assert!(!cert_pem.is_empty(), "Certificate PEM should not be empty");
        assert!(!key_pem.is_empty(), "Key PEM should not be empty");

        // Check that the certificate and key match
        let pubkey_from_cert = cert.public_key().expect("Failed to extract public key from cert");
        assert!(
            pubkey_from_cert.public_eq(&key),
            "Certificate public key does not match private key"
        );

        // Check that the subject CN is correct
        let subject = cert.subject_name();
        let cn_entry = subject.entries_by_nid(Nid::COMMONNAME).next();
        assert!(cn_entry.is_some(), "Certificate should have a CN entry");
        let cn = cn_entry.unwrap().data().as_utf8().unwrap().to_string();
        assert_eq!(cn, "test.example.local");

        // Check that the issuer and subject are the same (self-signed CA)
        let issuer = cert.issuer_name();
        assert_eq!(
            issuer.to_der().unwrap(),
            subject.to_der().unwrap(),
            "Issuer and subject should be identical"
        );

    }

    #[test]
    fn test_generate_leaf_cert() {
        // Generate a CA cert and key
        let (ca_cert, ca_key) = generate_ca_cert("test-ca.example.local");

        // Generate a leaf cert and key signed by the CA
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (leaf_cert, leaf_key) = rt.block_on(get_leaf_cert(&ca_cert, &ca_key, "leaf.example.com", false));

        // Check that the leaf certificate and key are not empty
        let cert_pem = leaf_cert.to_pem().expect("Failed to encode leaf cert to PEM");
        let key_pem = leaf_key.private_key_to_pem_pkcs8().expect("Failed to encode leaf key to PEM");
        assert!(!cert_pem.is_empty(), "Leaf certificate PEM should not be empty");
        assert!(!key_pem.is_empty(), "Leaf key PEM should not be empty");

        // Check that the leaf certificate and key match
        let pubkey_from_cert = leaf_cert.public_key().expect("Failed to extract public key from leaf cert");
        assert!(
            pubkey_from_cert.public_eq(&leaf_key),
            "Leaf certificate public key does not match private key"
        );

        // Check that the issuer of the leaf certificate matches the subject of the CA certificate
        let leaf_issuer = leaf_cert.issuer_name();
        let ca_subject = ca_cert.subject_name();
        assert_eq!(
            leaf_issuer.to_der().unwrap(),
            ca_subject.to_der().unwrap(),
            "Leaf certificate issuer should match CA subject"
        );

        // Check that the subject CN is correct
        let subject = leaf_cert.subject_name();
        let cn_entry = subject.entries_by_nid(openssl::nid::Nid::COMMONNAME).next();
        assert!(cn_entry.is_some(), "Leaf certificate should have a CN entry");
        let cn = cn_entry.unwrap().data().as_utf8().unwrap().to_string();
        assert_eq!(cn, "leaf.example.com");

        // Verify that the leaf certificate was signed by the CA
        assert!(
            leaf_cert.verify(&ca_key).unwrap(),
            "Leaf certificate signature could not be verified with CA key"
        );
        
    }
}
