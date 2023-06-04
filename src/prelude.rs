use std::sync::Arc;

use crate::client::{RaTlsClientCertResolver, RaTlsServerCertVerifier};
use crate::error::RaTlsError;
use crate::server::{RaTlsClientCertVerifier, RaTlsServerCertResolver};
use occlum_sgx::SGXQuote;
use rustls::{ClientConfig, ServerConfig};

pub use occlum_sgx::SGXMeasurement;

pub struct RaTlsConfig {
    pub(crate) mrsigner: Option<SGXMeasurement>,
    pub(crate) mrenclave: Option<SGXMeasurement>,
    pub(crate) product_id: Option<u16>,
    pub(crate) version: Option<u16>,
}

impl RaTlsConfig {
    pub fn new() -> Self {
        Self {
            mrsigner: None,
            mrenclave: None,
            product_id: None,
            version: None,
        }
    }

    pub fn with_mrsigner(self, mrsigner: SGXMeasurement) -> Self {
        Self {
            mrsigner: Some(mrsigner),
            ..self
        }
    }

    pub fn with_mrenclave(self, mrenclave: SGXMeasurement) -> Self {
        Self {
            mrenclave: Some(mrenclave),
            ..self
        }
    }

    pub fn with_product_id(self, product_id: u16) -> Self {
        Self {
            product_id: Some(product_id),
            ..self
        }
    }

    pub fn with_version(self, version: u16) -> Self {
        Self {
            version: Some(version),
            ..self
        }
    }

    pub(crate) fn verify_quote(&self, quote: &SGXQuote) -> Result<(), RaTlsError> {
        if let Some(mrsigner) = &self.mrsigner {
            let value = quote.mrsigner();
            if value != *mrsigner {
                return Err(RaTlsError::QuoteVerifyError(format!(
                    "MRSigner mismatch: {} != {}",
                    value, mrsigner
                )));
            }
        }
        if let Some(mrenclave) = &self.mrenclave {
            let value = quote.mrenclave();
            if value != *mrenclave {
                return Err(RaTlsError::QuoteVerifyError(format!(
                    "MREnclave mismatch: {} != {}",
                    value, mrenclave
                )));
            }
        }

        if let Some(product_id) = &self.product_id {
            let value = quote.product_id();
            if value != *product_id {
                return Err(RaTlsError::QuoteVerifyError(format!(
                    "ProductId mismatch: {} != {}",
                    value, product_id
                )));
            }
        }

        if let Some(version) = &self.version {
            let value = quote.version();
            if value != *version {
                return Err(RaTlsError::QuoteVerifyError(format!(
                    "Version mismatch: {} != {}",
                    value, version
                )));
            }
        }

        Ok(())
    }
}

pub trait RaTlsConfigBuilder<T> {
    fn from_ratls_config(config: RaTlsConfig) -> T;
}

impl RaTlsConfigBuilder<ServerConfig> for ServerConfig {
    fn from_ratls_config(config: RaTlsConfig) -> ServerConfig {
        ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(RaTlsClientCertVerifier::new(config)))
            .with_cert_resolver(Arc::new(RaTlsServerCertResolver::new()))
    }
}

impl RaTlsConfigBuilder<ClientConfig> for ClientConfig {
    fn from_ratls_config(config: RaTlsConfig) -> ClientConfig {
        ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(RaTlsServerCertVerifier::new(config)))
            .with_client_cert_resolver(Arc::new(RaTlsClientCertResolver::new()))
    }
}
