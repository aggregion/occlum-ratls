use std::net::SocketAddr;

use actix_web::{get, App, HttpServer};
use occlum_ratls::server_tsl_config;

#[get("/")]
async fn index() -> String {
    format!("Hello world!") // <- response with app_name
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let addr = SocketAddr::from(([127, 0, 0, 1], 8000));
    HttpServer::new(|| App::new().service(index))
        .bind_rustls(addr, server_tsl_config())
        .unwrap()
        .run()
        .await
}
