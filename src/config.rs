use crate::error::RaTlsError;
use occlum_sgx::SGXQuote;

pub use occlum_sgx::SGXMeasurement;

#[derive(Default)]
pub struct RaTlsConfig {
    pub(crate) mrsigner: Option<SGXMeasurement>,
    pub(crate) mrenclave: Option<SGXMeasurement>,
    pub(crate) product_id: Option<u16>,
    pub(crate) version: Option<u16>,
}

impl RaTlsConfig {
    pub fn new() -> Self {
        Self::default()
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
