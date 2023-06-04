use occlum_ratls::prelude::*;
use reqwest::ClientBuilder;
use rustls::ClientConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let client = ClientBuilder::new()
        .use_preconfigured_tls(ClientConfig::from_ratls_config(
            RaTlsConfig::new()
                .with_mrsigner(
                    SGXMeasurement::from_hex(
                        "e10eb055074ac2e47c9427c1a13e3129ba344ea1554c37cea8085a9295dcf288",
                    )
                    .unwrap(),
                )
                .with_product_id(1001),
        ))
        .build()?;
    let res = client.get("https://127.0.0.1:8000").send().await?;
    let data = res.text().await?;

    println!("response: {}", data);

    Ok(())
}
