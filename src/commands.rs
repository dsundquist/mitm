use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

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

#[derive(Args)]
pub struct StartArgs {
    /// CA_File to use, if necessary
    #[arg(long, short = 'c')]
    pub ca_file: Option<String>,
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
    Clear,
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
    /// Common name of a cert to generate and sign by the certificate authority
    #[arg(long, short = 'c')]
    pub san_name: String,
}
