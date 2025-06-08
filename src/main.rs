mod ca; // rcgen code
mod commands; // clap derive code
mod proxy; // pingora impl code

use clap::Parser;
use env_logger::Env;
use log::info;
use pingora::prelude::*;
use pingora::server::configuration::ServerConf;

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
        Some(commands::Commands::Test) => {
            handle_test_command();
        }
        Some(commands::Commands::Start(start_args)) => {
            handle_start_command(start_args);
        }
        None => {
            let start_args = commands::StartArgs::default();
            handle_start_command(start_args);
        }
    }
}

fn handle_ca_init_command() -> rcgen::CertifiedKey {
    ca::get_certificate_authority()
}

fn handle_ca_sign_command(sign_args: commands::CASignArgs) {
    ca::get_leaf_cert_rcgen(&sign_args.san_name);
}

fn handle_ca_clear_command(clear_args: commands::CAClearArgs) {
    ca::clear_config_directory(clear_args.execept_ca);
}

fn handle_start_command(start_args: commands::StartArgs) {
    ca::get_certificate_authority();

    // Create a ServerConf first, so that we can specify the ca
    let ca_file = start_args.ca_file.clone();
    let config = ServerConf {
        ca_file,
        ..Default::default()
    };

    // And we're not creating this from arguments, but manually
    let mut my_server = Server::new_with_opt_and_conf(None, config.validate().unwrap());

    my_server.bootstrap();

    info!("Start Args: \n{:?}", start_args);

    let inner = proxy::Mitm {
        verify_cert: !start_args.ignore_cert,
        verify_hostname: !start_args.ignore_hostname_check,
        origin: start_args.origin,
    };

    info!("Setting verify_cert to {}", inner.verify_cert);
    let mut my_service = http_proxy_service(&my_server.configuration, inner);

    let cert_provider = Box::new(proxy::MyCertProvider::new());

    // Keeping this for a reference:
    // let mut tls_settings = pingora::listeners::tls::TlsSettings::intermediate("bogus", "bogus").unwrap(); 

    let mut tls_settings = pingora::listeners::tls::TlsSettings::with_callbacks(cert_provider).unwrap();
    tls_settings.enable_h2();

    my_service.add_tls_with_settings("127.0.0.1:6188", None, tls_settings);

    my_server.add_service(my_service);

    my_server.run_forever();
}

fn handle_test_command() {
    ()
}