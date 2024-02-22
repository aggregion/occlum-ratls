use rustls::{
    server::{ClientCertVerified, ClientCertVerifier, ResolvesServerCert},
    sign::CertifiedKey,
    Certificate, DistinguishedName, Error, ServerConfig,
};
use std::{sync::Arc, time::SystemTime};

use crate::{
    cert::{CertificateBuilder, RaTlsCertificate, RaTlsCertificateBuilder},
    RaTlsConfig, RaTlsConfigBuilder, RaTlsError,
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
        end_entity.verify_quote(&self.config).map_err(|e| {
            println!("{:?}", e);
            rustls::Error::General(e.to_string())
        })?;

        Ok(ClientCertVerified::assertion())
    }

    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
}

pub struct RaTlsServerCertResolver {
    cert: Arc<CertifiedKey>,
}

impl RaTlsServerCertResolver {
    pub fn new() -> Result<Self, RaTlsError> {
        let builder = RaTlsCertificateBuilder::new().with_common_name("Client".to_string());
        let cert = builder.build().map(Arc::new)?;
        Ok(Self { cert })
    }
}

impl ResolvesServerCert for RaTlsServerCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<std::sync::Arc<CertifiedKey>> {
        Some(self.cert.clone())
    }
}

impl RaTlsConfigBuilder<ServerConfig> for ServerConfig {
    fn from_ratls_config(config: RaTlsConfig) -> Result<Self, RaTlsError> {
        Ok(Self::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(RaTlsClientCertVerifier::new(config)))
            .with_cert_resolver(Arc::new(RaTlsServerCertResolver::new()?)))
    }
}
