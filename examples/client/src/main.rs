use ratls::client_tls_config;
use reqwest::ClientBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder().filter_level(log::LevelFilter::Info).parse_env("LOG_LEVEL").init();

    let client = ClientBuilder::new().use_preconfigured_tls(client_tls_config()).build()?;

    let res = client.get("https://localhost:8000").send().await?;

    println!("{:#?}", res);

    Ok(())
}