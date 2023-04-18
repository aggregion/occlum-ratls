use std::net::SocketAddr;

use actix_web::{ HttpServer, App, get };
use ratls::server_tsl_config;
#[get("/")]
async fn index() -> String {
    format!("Hello world!") // <- response with app_name
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8000));

    env_logger::builder().filter_level(log::LevelFilter::Trace).build();
    env_logger::init();

    HttpServer::new(|| App::new().service(index))
        .bind_rustls(addr, server_tsl_config())
        .unwrap()
        .run().await
}