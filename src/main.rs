mod ca; // rcgen code
mod commands; // clap derive code
mod proxy; // pingora impl code

use clap::Parser;
use env_logger::Env;
use log::info;
use pingora::prelude::*;
use pingora::server::configuration::ServerConf;
use tokio::runtime::Runtime;

fn main() {
    // We need some sort of logging... this'll do:
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
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
            info!("Start Args: \n{:?}", start_args);

            if start_args.wireshark_mode.is_none() {
                handle_start_command(start_args);
            } else {
                handle_start_wireshark_mode(start_args);
            }
        }
        None => {
            let start_args = commands::StartArgs::default();
            handle_start_command(start_args);
        }
    }
}

fn handle_ca_init_command() -> rcgen::CertifiedKey {
    let rt = Runtime::new().unwrap();
    rt.block_on(ca::get_certificate_authority())
}

fn handle_ca_sign_command(sign_args: commands::CASignArgs) {
    let rt = Runtime::new().unwrap();
    rt.block_on(ca::get_leaf_cert_rcgen(&sign_args.san_name));
}

fn handle_ca_clear_command(clear_args: commands::CAClearArgs) {
    let rt = Runtime::new().unwrap();
    rt.block_on(ca::clear_config_directory(clear_args.execept_ca));
}

fn handle_start_command(start_args: commands::StartArgs) {

    let mut my_server = get_server_from_start_args(&start_args);

    let inner = proxy::Mitm {
        verify_cert: !start_args.ignore_cert,
        verify_hostname: !start_args.ignore_hostname_check,
        upstream: start_args.upstream,
        upstream_sni: start_args.sni,
        upstream_tls: true,
    };

    info!("Setting verify_cert to {}", inner.verify_cert);
    let mut my_service = http_proxy_service(&my_server.configuration, inner);

    let cert_provider = Box::new(proxy::MyCertProvider::new());

    // Keeping this for a reference:
    // let mut tls_settings = pingora::listeners::tls::TlsSettings::intermediate("bogus", "bogus").unwrap(); 

    let mut tls_settings = pingora::listeners::tls::TlsSettings::with_callbacks(cert_provider).unwrap();
    tls_settings.enable_h2();

    let socket_addr = format!("127.0.0.1:{}", start_args.listening_port);
    info!("Listening on: {}", &socket_addr);

    my_service.add_tls_with_settings(&socket_addr, None, tls_settings);

    my_server.add_service(my_service);

    my_server.run_forever();

}

fn handle_start_wireshark_mode(start_args: commands::StartArgs) {
    info!("Starting in Wireshark mode");
    let loopback_port = start_args.wireshark_mode.unwrap();
    let loopback_ip_port = format!("127.0.0.1:{}", loopback_port);

    let mut my_server = get_server_from_start_args(&start_args);

    // Now we need two services...
    // [Client] -> [Service A] -> [Service B] -> [Upstream]
    // Where communications from Serivce A to Service B is regular http. 
    // That is the Connector on Service A and the Listener on Service B do not use TLS. 
    // The Listener on Service A and Connector on Service B do use TLS
    let mitm_service_a = proxy::Mitm {
        verify_cert: !start_args.ignore_cert,
        verify_hostname: !start_args.ignore_hostname_check,
        upstream: Some(loopback_ip_port.clone()),
        upstream_sni: start_args.sni.clone(),
        upstream_tls: false,
    };

    let mitm_service_b = proxy::Mitm {
        verify_cert: !start_args.ignore_cert,
        verify_hostname: !start_args.ignore_hostname_check,
        upstream: start_args.upstream,
        upstream_sni: start_args.sni.clone(),
        upstream_tls: true,
    };

    // Setup Service A
    let mut service_a = http_proxy_service(&my_server.configuration, mitm_service_a);
    let cert_provider = Box::new(proxy::MyCertProvider::new());
    let mut tls_settings = pingora::listeners::tls::TlsSettings::with_callbacks(cert_provider).unwrap();
    tls_settings.enable_h2();

    let socket_addr = format!("127.0.0.1:{}", start_args.listening_port);
    info!("Listening on: {}", &socket_addr);

    service_a.add_tls_with_settings(&socket_addr, None, tls_settings);

    // Setup Service B
    let mut service_b = http_proxy_service(&my_server.configuration, mitm_service_b);
    service_b.add_tcp(&loopback_ip_port);

    // Add both to server
    my_server.add_service(service_a);
    my_server.add_service(service_b);

    my_server.run_forever();
}

fn get_server_from_start_args(start_args: &commands::StartArgs) -> Server {
     // Create a ServerConf first, so that we can specify the ca
    let ca_file = start_args.ca_file.clone();
    let config = ServerConf {
        ca_file,
        upstream_debug_ssl_keylog: start_args.upstream_ssl_keys,
        ..Default::default()
    };

    // And we're not creating this from arguments, but manually
    let mut server = Server::new_with_opt_and_conf(None, config.validate().unwrap());

    server.bootstrap();

    server   
}