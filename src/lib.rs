use config::RaTlsConfig;

mod cert;
mod client;
mod config;
mod error;
mod server;
mod utils;

pub mod prelude;

pub use crate::error::RaTlsError;

pub trait RaTlsConfigBuilder<T> {
    fn from_ratls_config(config: RaTlsConfig) -> T;
}
