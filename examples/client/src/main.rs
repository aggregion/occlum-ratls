use ratls::client_tls_config;
use reqwest::ClientBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let client = ClientBuilder::new().use_preconfigured_tls(client_tls_config()).build()?;
    let res = client.get("https://127.0.0.1:8000").send().await?;
    let data = res.text().await?;

    println!("response: {}", data);

    Ok(())
}