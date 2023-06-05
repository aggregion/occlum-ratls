mod cert;
mod client;
mod config;
mod error;
mod http;
mod server;
mod utils;

pub mod prelude;

pub use crate::config::RaTlsConfig;
pub use crate::error::RaTlsError;
pub use occlum_sgx::SGXMeasurement;

#[cfg(feature = "actix-web")]
pub use crate::http::actix_web;

#[cfg(feature = "reqwest")]
pub use crate::http::reqwest;

pub trait RaTlsConfigBuilder<T> {
    fn from_ratls_config(config: RaTlsConfig) -> T;
}
