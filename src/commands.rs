use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::default::Default;

#[derive(Parser)]
#[command(
    name = "mitm",
    version = "1.0",
    about = "CLI for a MITM https proxy - built using Pingora"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the MITM Proxy
    Start(StartArgs),
    /// Run CA related commands
    CA(CAArgs),
}

#[derive(Args, Debug)]
pub struct StartArgs {
    /// Proxy listening port
    #[arg(long, short = 'p', default_value_t = 6188)]
    pub listening_port: u16,
    /// Optional CA_File to use for the upstream TLS connection. 
    #[arg(long, short = 'c')]
    pub ca_file: Option<String>,
    /// Ignore the upstream hostname check, Default = False
    #[arg(long, short = 'i', default_value_t = false)]
    pub ignore_hostname_check: bool,
    /// Ignore the upstream certificate, Default = False
    #[arg(long, short = 'k', default_value_t = false)]
    pub ignore_cert: bool,
    /// Set the upstream SNI, otherwise uses the downstream SNI
    #[arg(long, short = 's')]
    pub sni: Option<String>,
    // This is ugly, but it does print out properly..
    #[arg(long, short = 'u',  help = r#"Specify a static origin for all upstream requests.
When not supplied, it'll dynamically look up upstream by downstream SNI (or hostname if it is http).
This is useful for testing or forcing all traffic to a single backend.
Takes SocketAddrs, Eg: "127.0.0.1:443", "localhost:443""#)]
    pub upstream: Option<String>,
    /// If this option is enabled, and the env variable SSLKEYLOGFILE is set, the upstream SSL keys will be written to that file. 
    #[arg(long, short = 't', default_value_t = false)]
    pub upstream_ssl_keys: bool,
    /// Pass a port number that all traffic will be routed through on localhost for wireshark capture.  
    #[arg(long, short = 'W')]
    pub wireshark_mode: Option<u16>,
    
}

impl Default for StartArgs {
    fn default() -> Self {
        StartArgs {
            listening_port: 6188,
            ca_file: None,
            ignore_hostname_check: false,
            ignore_cert: false,
            sni: None,
            upstream: Some("127.0.0.1:443".to_string()),
            upstream_ssl_keys: false,
            wireshark_mode: None,
        }
    }
}

#[derive(Args)]
pub struct CAArgs {
    #[command(subcommand)]
    pub subcommand: CASubcommand,
}

#[derive(Subcommand)]
pub enum CASubcommand {
    /// Initialize the certificate authority
    Init(CAInitArgs),
    /// Sign a certificate with a SAN by the CA
    Sign(CASignArgs),
    /// Clears the config directory
    Clear(CAClearArgs),
}

#[derive(Args)]
pub struct CAInitArgs {
    /// Path to the CA
    #[arg(long, short = 'p')]
    pub cert_path: Option<PathBuf>,

    /// Name of the certificate key file
    #[arg(long, short = 'k')]
    pub key_name: Option<PathBuf>,

    /// Name of the public certificate file
    #[arg(long, short = 'c')]
    pub cert_name: Option<PathBuf>,
}

#[derive(Args)]
pub struct CASignArgs {
    /// Used to fill the Common Name and Subject Alternative Name of the Leaf Certificate.
    #[arg(long, short = 's')]
    pub san_name: String,
}

#[derive(Args)]
pub struct CAClearArgs {
    /// Do not clear the ca files (ca.crt and ca.key)
    #[arg(long, short = 'x', default_value_t = false)]
    pub execept_ca: bool,
}
