use crate::RaTlsConfigBuilder;

#[cfg(feature = "occlum")]
use crate::error::RaTlsError;
#[cfg(feature = "occlum")]
use occlum_sgx::SGXQuote;

pub use occlum_sgx::SGXMeasurement;
use rustls::{ClientConfig, ServerConfig};

#[derive(Default)]
pub struct RaTlsConfig {
    #[cfg(feature = "occlum")]
    pub(crate) allowed_instances: Vec<InstanceMeasurement>,
}

#[cfg(feature = "occlum")]
#[derive(Default, Clone)]
pub struct InstanceMeasurement {
    pub(crate) mrsigners: Option<Vec<SGXMeasurement>>,
    pub(crate) mrenclaves: Option<Vec<SGXMeasurement>>,
    pub(crate) product_ids: Option<Vec<u16>>,
    pub(crate) versions: Option<Vec<u16>>,
}

#[cfg(feature = "occlum")]
impl InstanceMeasurement {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_mrsigners(self, mrsigners: Vec<SGXMeasurement>) -> Self {
        Self {
            mrsigners: Some(mrsigners),
            ..self
        }
    }

    pub fn with_mrenclaves(self, mrenclaves: Vec<SGXMeasurement>) -> Self {
        Self {
            mrenclaves: Some(mrenclaves),
            ..self
        }
    }

    pub fn with_product_ids(self, product_ids: Vec<u16>) -> Self {
        Self {
            product_ids: Some(product_ids),
            ..self
        }
    }

    pub fn with_versions(self, versions: Vec<u16>) -> Self {
        Self {
            versions: Some(versions),
            ..self
        }
    }

    pub(crate) fn check_quote_measurements(&self, quote: &SGXQuote) -> bool {
        let mut result = false;
        if let Some(mrsigners) = &self.mrsigners {
            result = true;
            let value = quote.mrsigner();
            if !mrsigners.contains(&value) {
                return false;
            }
        }
        if let Some(mrenclaves) = &self.mrenclaves {
            result = true;
            let value = quote.mrenclave();
            if !mrenclaves.contains(&value) {
                return false;
            }
        }

        if let Some(product_ids) = &self.product_ids {
            result = true;
            let value = quote.product_id();
            if !product_ids.contains(&value) {
                return false;
            }
        }

        if let Some(versions) = &self.versions {
            result = true;
            let value = quote.version();
            if !versions.contains(&value) {
                return false;
            }
        }

        result
    }
}

impl RaTlsConfig {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "occlum")]
    pub fn allow_instance_measurement(mut self, instance_measurement: InstanceMeasurement) -> Self {
        self.allowed_instances.push(instance_measurement);
        self
    }

    #[cfg(feature = "occlum")]
    pub(crate) fn is_allowed_quote(&self, quote: &SGXQuote) -> Result<(), RaTlsError> {
        match self
            .allowed_instances
            .iter()
            .any(|im| im.check_quote_measurements(quote))
        {
            true => Ok(()),
            false => Err(RaTlsError::QuoteVerifyError(format!(
                "{:?} is not allowed",
                quote
            ))),
        }
    }

    pub fn into_server_config(self) -> ServerConfig {
        ServerConfig::from_ratls_config(self)
    }

    pub fn into_client_config(self) -> ClientConfig {
        ClientConfig::from_ratls_config(self)
    }
}
