mod ca; // rcgen code
mod commands; // clap derive code
mod proxy; // pingora impl code

use clap::Parser;
use env_logger::Env;
use log::{info, debug};
use pingora::prelude::*;
use tokio::runtime::Runtime;

fn main() {
    // Logging uses the env variable "RUST_LOG", otherwise info
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
            debug!("Start Args: \n{:?}", start_args);

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
    info!("Running proxy in normal mode");

    // A Pingora HttpProxy goes:
    // 1. First Create a Server, from a ServerConf: 
    let mut my_server = Server::from(start_args.clone());

    // 2. Define an inner type of the an HttpProxy (something that implements ProxyHttp)
    let inner = proxy::Mitm {
        name: String::from("MITM Service"),
        verify_cert: !start_args.ignore_cert,
        verify_hostname: !start_args.ignore_hostname_check,
        upstream: start_args.upstream,
        upstream_sni: start_args.sni,
        upstream_tls: true,
    };
    
    debug!("HttpProxy: {:?}", inner);
    info!("Upstream: {:?}", inner);
    info!("Listening on:  {:?}", start_args.listening_socket_addr);
    info!("Upstream: {:?}", start_args.upstream);

    // -- These steps are necessary for our custom, just-in-time certificate generation: 
    let cert_provider = Box::new(proxy::MyCertProvider::new());
    let mut tls_settings = pingora::listeners::tls::TlsSettings::with_callbacks(cert_provider).unwrap();
    tls_settings.enable_h2(); 

    // 3. Wrap our ProxyHttp in a HttpProxy, which gets wrapped in a Service 
    let mut my_service = http_proxy_service(&my_server.configuration, inner);
    my_service.add_tls_with_settings(&start_args.listening_socket_addr.to_string(), None, tls_settings);

    // 4. The service needs to be added to the Server 
    my_server.add_service(my_service);

    // 5. The server is then ran which spawns up a Tokio runtime. 
    //    It is for that reason, this function is not async 
    my_server.run_forever();

}

fn handle_start_wireshark_mode(start_args: commands::StartArgs) {
    info!("Running proxy in Wireshark mode");
    
    let loopback_port = start_args.wireshark_mode.unwrap();
    let loopback_ip_port = format!("127.0.0.1:{}", loopback_port);

    let mut my_server = Server::from(start_args.clone());

    // Now we need two services...
    // [Client] -> [Service A] -> [Service B] -> [Upstream]
    // Where communications from Serivce A to Service B is regular http. 
    // That is the Connector on Service A and the Listener on Service B do not use TLS. 
    // The Listener on Service A and Connector on Service B do use TLS
    let mitm_service_a = proxy::Mitm {
        name: String::from("MITM Service A"),
        verify_cert: !start_args.ignore_cert,
        verify_hostname: !start_args.ignore_hostname_check,
        upstream: Some(loopback_ip_port.clone().parse().unwrap()),
        upstream_sni: start_args.sni.clone(),
        upstream_tls: false,
    };

    let mitm_service_b = proxy::Mitm {
        name: String::from("MITM Service B"),
        verify_cert: !start_args.ignore_cert,
        verify_hostname: !start_args.ignore_hostname_check,
        upstream: start_args.upstream,
        upstream_sni: start_args.sni.clone(),
        upstream_tls: true,
    };

    debug!("Service A: {:?}", mitm_service_a);
    debug!("Service B: {:?}", mitm_service_b);
    info!("Created HttpProxy:");
    info!("Listening on:   {}", &start_args.listening_socket_addr);
    info!("Wireshark port: 127.0.0.1:{}", loopback_port);
    info!("Upstream:  {:?}", start_args.upstream);

    // Setup Service A
    let mut service_a = http_proxy_service(&my_server.configuration, mitm_service_a);
    let cert_provider = Box::new(proxy::MyCertProvider::new());
    let mut tls_settings = pingora::listeners::tls::TlsSettings::with_callbacks(cert_provider).unwrap();
    tls_settings.enable_h2();
    service_a.add_tls_with_settings(&start_args.listening_socket_addr.to_string(), None, tls_settings);

    // Setup Service B
    let mut service_b = http_proxy_service(&my_server.configuration, mitm_service_b);
    service_b.add_tcp(&loopback_ip_port);

    // Add both to server
    my_server.add_service(service_a);
    my_server.add_service(service_b);

    my_server.run_forever();
}