use rcgen::Certificate;

#[allow(dead_code)]
fn generate_ca_cert() -> Certificate {
    unimplemented!();
}

#[allow(dead_code)]
fn generate_leaf_cert(_ca_cert: &Certificate, _hostname: &str) -> (Vec<u8>, Vec<u8>) {
    unimplemented!();
}
