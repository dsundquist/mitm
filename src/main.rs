mod ca; // rcgen code
mod commands; // clap derive code
mod proxy; // pingora impl code

use clap::Parser;
use env_logger::Env;
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
            commands::CASubcommand::Clear(clear_args) => {
                handle_ca_clear_command(clear_args);
            }
        },
        Some(commands::Commands::Start(start_args)) => {
            handle_serve_command(start_args);
        }
        None => {
            let start_args = commands::StartArgs { ca_file: None };
            handle_serve_command(start_args);
        }
    }
}

fn handle_ca_init_command() -> rcgen::CertifiedKey {
    ca::get_certificate_authority()
}

fn handle_ca_sign_command(sign_args: commands::CASignArgs) {
    ca::get_leaf_cert(&sign_args.san_name);
}

fn handle_ca_clear_command(clear_args: commands::CAClearArgs) {
    ca::clear_config_directory(clear_args.execept_ca);
}

fn handle_serve_command(start_args: commands::StartArgs) {
    ca::get_certificate_authority();

    // Create a ServerConf first, so that we can specify the ca
    let config = ServerConf {
        ca_file: start_args.ca_file,
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
    let cert_path = "/home/hans/.mitm/example.sundquist.net.crt";
    let key_path = "/home/hans/.mitm/example.sundquist.net.key";
    lb.add_tls(addr, cert_path, key_path).unwrap();

    my_server.add_service(lb);

    my_server.run_forever();
}
