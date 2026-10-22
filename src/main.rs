use std::{fs::File, io::Read, path::Path, sync::Arc};

use axum::body::Body;
use gumdrop::Options;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use log::{LevelFilter, debug};
use sekai_injector::{
    Config, Manager, ServerStatistics, certificates::generate_certs_interactive,
    load_injection_maps, server,
};
use tokio::sync::RwLock;

#[derive(Debug, Options)]
struct CommandOptions {
    #[options(help = "print help message")]
    help: bool,
    #[options(help = "be verbose")]
    verbose: bool,
    #[options(help = "specify a specific config file")]
    config: Option<String>,

    #[options(command)]
    command: Option<Command>,
}

#[derive(Debug, Options)]
enum Command {
    #[options(help = "start the server")]
    Start(StartOptions),

    #[options(help = "interactively generate CA and certificates")]
    GenerateCerts(GenerateCertsOptions),
}

#[derive(Debug, Options)]
struct StartOptions {}

#[derive(Debug, Options)]
struct GenerateCertsOptions {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = CommandOptions::parse_args_default_or_exit();

    let mut builder = env_logger::Builder::new();

    if opts.verbose {
        builder.filter_level(LevelFilter::Debug);
    } else {
        builder.filter_level(LevelFilter::Info);
    }
    builder.init();

    let config_path = match opts.config {
        Some(config) => config,
        None => "sekai-injector.toml".to_string(),
    };

    debug!("Using config: {config_path}");

    let config_path = Path::new(&config_path);

    let mut config_file_contents = String::new();
    let mut config_file =
        File::open(config_path).expect("Could not open config file. Do I have permission?");
    config_file
        .read_to_string(&mut config_file_contents)
        .expect(
            "The config file contains non UTF-8 characters, what in the world did you put in it??",
        );
    let config_holder: Config = toml::from_str(&config_file_contents)
        .expect("The config file was not formatted properly and could not be read.");

    if let Some(Command::GenerateCerts(ref _generate_certs_options)) = opts.command {
        generate_certs_interactive(&config_holder);
    } else if let Some(Command::Start(ref _start_options)) = opts.command {
        let injection_hashmap = load_injection_maps(&config_holder);

        // Create a client to handle making HTTPS requests
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()?
            .https_or_http()
            .enable_all_versions()
            .build();

        let client = Client::builder(TokioExecutor::new()).build::<_, Body>(https);

        // Create manager containing our config and injection_hashmap and HTTPS client
        let manager = Arc::new(RwLock::new(Manager {
            injection_hashmap,
            config: config_holder,
            client,
            statistics: ServerStatistics {
                request_count: (0, 0),
                requests: Vec::new(),
            },
        }));

        server::serve(manager).await;
    }

    Ok(())
}
