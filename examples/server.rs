use occlum_ratls::{
    actix_web::{get, App, HttpServer},
    prelude::*,
};
use std::net::SocketAddr;

#[get("/")]
async fn index() -> String {
    format!("Hello world!") // <- response with app_name
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("trace"));

    HttpServer::new(|| App::new().service(index))
        .bind_ratls(
            SocketAddr::from(([127, 0, 0, 1], 8000)),
            RaTlsConfig::new().with_mrsigner(
                SGXMeasurement::from_hex(
                    "e10eb055074ac2e47c9427c1a13e3129ba344ea1554c37cea8085a9295dcf288",
                )
                .unwrap(),
            ),
        )
        .unwrap()
        .run()
        .await
}
