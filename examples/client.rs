use occlum_ratls::prelude::*;
use reqwest::ClientBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("trace"));
    let client = ClientBuilder::new()
        .use_ratls(
            RaTlsConfig::new().allow_instance_measurement(
                InstanceMeasurement::new()
                    .with_mrsigners(vec![SGXMeasurement::new([0u8; 32])])
                    .with_product_ids(vec![1]),
            ),
        )
        .build()?;
    let res = client.get("https://127.0.0.1:8000").send().await?;
    let data = res.text().await?;

    println!("response: {}", data);

    Ok(())
}
