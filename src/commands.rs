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
    /// Delete me - for testing scenarios 
    Test
}

#[derive(Args)]
pub struct StartArgs {
    /// Optional CA_File to use for the upstream TLS connection. 
    #[arg(long, short = 'c')]
    pub ca_file: Option<String>,
    /// Ignore the upstream certificate, Default = False
    #[arg(long, short = 'k', default_value_t = false)]
    pub ignore_cert: bool,
    /// Use the SNI to lookup the origin
    #[arg(long, short = 'd', default_value_t = false)]
    pub dynamic_origin: bool,
}

impl Default for StartArgs {
    fn default() -> Self {
        StartArgs {
            ca_file: None,
            ignore_cert: false,
            dynamic_origin: false,
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
