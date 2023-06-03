pub mod cert;
pub mod client;
pub mod error;
pub mod server;
mod utils;

use std::sync::Arc;

use client::{RaTlsClientCertResolver, RaTlsServerCertVerifier};
use rustls::{ClientConfig, ServerConfig};
use server::{RaTlsClientCertVerifier, RaTlsServerCertResolver};

pub fn server_tsl_config() -> ServerConfig {
    ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(RaTlsClientCertVerifier::new()))
        .with_cert_resolver(Arc::new(RaTlsServerCertResolver::new()))
}

pub fn client_tls_config() -> ClientConfig {
    ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(RaTlsServerCertVerifier::new()))
        .with_client_cert_resolver(Arc::new(RaTlsClientCertResolver::new()))
}
