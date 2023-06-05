use rustls::{
    server::{ClientCertVerified, ClientCertVerifier, ResolvesServerCert},
    Certificate, DistinguishedNames, Error, ServerConfig,
};
use std::{sync::Arc, time::SystemTime};

use crate::{
    cert::{CertificateBuilder, RaTlsCertificate, RaTlsCertificateBuilder},
    RaTlsConfig, RaTlsConfigBuilder,
};

pub struct RaTlsClientCertVerifier {
    config: RaTlsConfig,
}

impl RaTlsClientCertVerifier {
    pub fn new(config: RaTlsConfig) -> Self {
        Self { config }
    }
}

impl ClientCertVerifier for RaTlsClientCertVerifier {
    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _now: SystemTime,
    ) -> Result<ClientCertVerified, Error> {
        end_entity
            .verify_quote(&self.config)
            .map_err(|e| rustls::Error::General(e.to_string()))?;

        Ok(ClientCertVerified::assertion())
    }

    fn client_auth_root_subjects(&self) -> Option<rustls::DistinguishedNames> {
        Some(DistinguishedNames::new())
    }
}

pub struct RaTlsServerCertResolver {
    cert: Option<std::sync::Arc<rustls::sign::CertifiedKey>>,
}

impl Default for RaTlsServerCertResolver {
    fn default() -> Self {
        let builder = RaTlsCertificateBuilder::new().with_common_name("Client".to_string());
        let cert = builder.build().ok().map(Arc::new);
        Self { cert }
    }
}

impl RaTlsServerCertResolver {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

impl ResolvesServerCert for RaTlsServerCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        self.cert.clone()
    }
}

impl RaTlsConfigBuilder<ServerConfig> for ServerConfig {
    fn from_ratls_config(config: RaTlsConfig) -> Self {
        Self::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(RaTlsClientCertVerifier::new(config)))
            .with_cert_resolver(Arc::new(RaTlsServerCertResolver::new()))
    }
}
