mod ca;
mod commands; // clap derive code
mod proxy; // pingora impl code // rcgen code 

use clap::Parser;
use env_logger::Env;
use pingora::prelude::*;
use pingora::server::configuration::ServerConf;

// use std::sync::Arc; // Could be used in CTX
// use log::{info, debug, warn, error}; // Could be used if we want to print some log messages

fn main() {
    let cli = commands::Cli::parse();

    match cli.command {
        Some(commands::Commands::CA(args)) => match args.subcommand {
            commands::CASubcommand::Init(init_args) => {
                handle_ca_init_command(init_args);
            }
        },
        Some(commands::Commands::Start(_args)) => {
            handle_serve_command();
        }
        None => {
            handle_serve_command();
        }
    }
}

fn handle_ca_init_command(_init_args: commands::CAInitArgs) {
    //
}

fn handle_serve_command() {
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

    let mut lb = http_proxy_service(&my_server.configuration, proxy::Mitm);

    // Just plain ol' tcp:
    // lb.add_tcp("127.0.0.1:6188");

    // With TLS, which we'll use the same cert for the gotestserver
    let addr = "127.0.0.1:6188";
    let cert_path = "/home/hans/go/bin/server.crt";
    let key_path = "/home/hans/go/bin/server.key";
    lb.add_tls(addr, cert_path, key_path).unwrap();

    my_server.add_service(lb);

    my_server.run_forever();
}
