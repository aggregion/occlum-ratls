use actix_web::{get, App, HttpServer};
use occlum_ratls::prelude::*;
use std::net::SocketAddr;

#[get("/")]
async fn index() -> String {
    format!("Hello world!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("trace"));

    HttpServer::new(|| App::new().service(index))
        .bind_ratls(
            SocketAddr::from(([127, 0, 0, 1], 8000)),
            RaTlsConfig::new()
                .allow_instance_measurement(
                    InstanceMeasurement::new().with_mrsigners(vec![SGXMeasurement::new([0u8; 32])]),
                )
                .allow_instance_measurement(
                    InstanceMeasurement::new()
                        .with_mrenclaves(vec![
                            SGXMeasurement::new([0u8; 32]),
                            SGXMeasurement::new([1u8; 32]),
                        ])
                        .with_product_ids(vec![2]),
                ),
        )
        .unwrap()
        .run()
        .await
}
