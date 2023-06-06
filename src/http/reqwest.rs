use reqwest::ClientBuilder;
use rustls::ClientConfig;

use crate::{RaTlsConfig, RaTlsConfigBuilder};

pub trait ReqwestUseRatls {
    fn use_ratls(self, config: RaTlsConfig) -> ClientBuilder;
}

impl ReqwestUseRatls for ClientBuilder {
    fn use_ratls(self, config: RaTlsConfig) -> ClientBuilder {
        self.use_preconfigured_tls(ClientConfig::from_ratls_config(config))
    }
}
