mod ca; // rcgen code
mod commands; // clap derive code
mod proxy; // pingora impl code // rcgen code 

use clap::Parser;
use env_logger::Env;
use log::info;
use pingora::prelude::*;
use pingora::server::configuration::ServerConf;

// use std::sync::Arc; // Could be used in CTX

fn main() {
    // We need some sort of logging... this'll do:
    env_logger::Builder::from_env(Env::default().default_filter_or("debug"))
        .format_target(true)
        .format_timestamp(Some(env_logger::TimestampPrecision::Seconds))
        .init();

    let cli = commands::Cli::parse();

    match cli.command {
        Some(commands::Commands::CA(args)) => match args.subcommand {
            commands::CASubcommand::Init(_init_args) => {
                handle_ca_init_command();
            }
            commands::CASubcommand::Sign(sign_args) => {
                handle_ca_sign_command(sign_args);
            }
            commands::CASubcommand::Clear => {
                handle_ca_clear_command();
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

fn handle_ca_sign_command(sign_args: commands::CASignArgs) {
    ca::get_leaf_cert(&sign_args.san_name);
}

fn handle_ca_init_command() -> rcgen::CertifiedKey {
    // Check that the config directory exists
    ca::get_certificate_authority()
}

fn handle_ca_clear_command() {
    info!("Clearing the config directory");
    ca::clear_config_directory();
}

fn handle_serve_command() {
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
