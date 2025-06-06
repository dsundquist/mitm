use log::info;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedKey, DistinguishedName, DnType, Error, IsCa,
    KeyPair, KeyUsagePurpose,
};
use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Get the mitm directory full path ($home/.mitm expanded)
/// TODO:  Likely use a dependency (dirs) to support additional platforms
fn get_mitm_directory() -> PathBuf {
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

/// Ensures that ~/.mitm/ exists, if it doesn't it'll create it
fn ensure_config_directory_exists() {
    let mitm_dir = get_mitm_directory();

    // Check existence and whether it's a directory
    if !mitm_dir.is_dir() {
        // Create the directory
        info!("Creating mitm config directory at {:?}", mitm_dir);
        fs::create_dir_all(&mitm_dir).unwrap();
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
fn get_from_config_directory(filename: &str) -> String {
    let file_path = get_mitm_directory().join(filename);
    std::fs::read_to_string(&file_path)
        .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", file_path, e))
}

/// This will write a file to ~/.mitm/, if it doesn't already exist
fn write_certificate_to_config_directory(
    file_name: &str,
    contents: String,
    permissions: Option<u32>,
) {
    let cert_path = get_mitm_directory().join(file_name);
    if cert_path.exists() {
        info!("File already exists, not overwriting: {:?}", cert_path);
        return;
    }
    let mut cert_file = File::create(&cert_path).unwrap();

    if let Some(permission) = permissions {
        info!("Setting permissions mode {:o}", permission);
        fs::set_permissions(&cert_path, fs::Permissions::from_mode(permission)).unwrap();
    }

    info!("Writing file: {:?}", cert_path);
    cert_file.write_all(contents.as_bytes()).unwrap();
}

/// Clears the config directory (~/.mitm) of all files 
pub fn clear_config_directory(save_ca_files: bool) {
    info!("Clearing the config directory");
    let mitm_dir = get_mitm_directory();
    for entry in fs::read_dir(mitm_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            if save_ca_files && (path.ends_with("ca.crt") || path.ends_with("ca.key")) {
                info!("Skipping CA File: {:?}", path);
            } else {
                fs::remove_file(&path).unwrap();
            }
        } else if path.is_dir() {
            // Optionally clear subdirectories recursively:
            fs::remove_dir_all(&path).unwrap();
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
pub fn get_certificate_authority() -> CertifiedKey {
    ensure_config_directory_exists();

    if !ca_files_exist() {
        // Generate, write, and return
        // If the file doesn't already create them, and save thme
        let cert = generate_ca_cert(vec!["test.example.local".to_string()]).unwrap();

        // public cert
        write_certificate_to_config_directory("ca.crt", cert.cert.pem(), Some(0o644));

        // private key
        write_certificate_to_config_directory("ca.key", cert.key_pair.serialize_pem(), Some(0o600));

        CertifiedKey {
            cert: cert.cert,
            key_pair: cert.key_pair,
        }
    } else {
        // Else load the CA, and return it
        // First the key
        let key_string = get_from_config_directory("ca.key");
        let key_pair = rcgen::KeyPair::from_pem(&key_string).unwrap();

        // Then the certificate
        let cert_string = get_from_config_directory("ca.crt");
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
pub fn get_leaf_cert(hostname: &str) -> CertifiedKey {
    let ca = get_certificate_authority();

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
    write_certificate_to_config_directory(&file_name, cert.pem(), Some(0o644));

    // then the private key
    let file_name = hostname.to_string() + ".key";
    write_certificate_to_config_directory(&file_name, key_pair.serialize_pem(), Some(0o600));

    CertifiedKey { cert, key_pair }
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
