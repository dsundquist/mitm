use async_trait::async_trait;
use clap::Parser;
use env_logger::Env;
// use std::sync::Arc;

use pingora::prelude::*;
use pingora::server::configuration::ServerConf;
use pingora::upstreams::peer::HttpPeer;

use crate::commands::CAInitArgs;
// use log::{info, debug, warn, error};

mod commands;

pub struct MITM;

#[async_trait]
impl ProxyHttp for MITM {

    /// For this small example, we don't need context storage
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut ()) -> Result<Box<HttpPeer>> {

        // println!("upstream peer is: {self.upstream:?}");

        // Set SNI to blank, which ignores any SNI checks for the Certificate?
        let peer = Box::new(HttpPeer::new("127.0.0.1:443", true, "localhost".to_string()));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request.insert_header("Host", "one.one.one.one").unwrap();
        Ok(())
    }
}

fn main() {
    let cli =  crate::commands::Cli::parse();

    match cli.command {
        Some(crate::commands::Commands::CA(args)) => {
            match args.subcommand {
                crate::commands::CASubcommand::Init(init_args) => {
                    handle_ca_init_command(init_args);
                }
            }
        }
        Some(crate::commands::Commands::Start(_args)) => {
            handle_serve_command();
        }
        None => {
            handle_serve_command();
        }
        
    }
}

fn handle_ca_init_command(_init_args: CAInitArgs){
    println!("Initializing CA");
}

fn handle_serve_command(){
    // We need some sort of logging... this'll do:
    env_logger::Builder::from_env(Env::default().default_filter_or("debug"))
        .format_target(true)
        .format_timestamp(Some(env_logger::TimestampPrecision::Seconds))
        .init();

    // Create a ServerConf first, so that we can specify the ca 
    let config = ServerConf {
        ca_file: Some(String::from("/home/hans/go/bin/server.crt")),
        ..Default::default()
    };

    // And we're not creating this from arguments, but manually
    let mut my_server = Server::new_with_opt_and_conf(None, config.validate().unwrap());

    my_server.bootstrap();

    // let upstreams =
    //     LoadBalancer::try_from_iter(["localhost:443"]).unwrap();

    let mut lb = http_proxy_service(&my_server.configuration, MITM);
    
    // Just plain ol' tcp: 
    // lb.add_tcp("127.0.0.1:6188");

    // With TLS, which we'll use the same cert for the gotestserver
    let addr = "127.0.0.1:6188";
    let cert_path =  "/home/hans/go/bin/server.crt";
    let key_path = "/home/hans/go/bin/server.key";
    lb.add_tls(addr, cert_path, key_path).unwrap();
 
    my_server.add_service(lb);

    my_server.run_forever();
}
