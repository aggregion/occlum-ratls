use std::sync::Arc;

use crate::{
    cert::{CertificateBuilder, RaTlsCertificate, RaTlsCertificateBuilder},
    RaTlsConfig, RaTlsConfigBuilder,
};
use rustls::{
    client::{ResolvesClientCert, ServerCertVerified, ServerCertVerifier},
    ClientConfig,
};

pub struct RaTlsServerCertVerifier {
    config: RaTlsConfig,
}

impl RaTlsServerCertVerifier {
    pub fn new(config: RaTlsConfig) -> Self {
        Self { config }
    }
}

impl ServerCertVerifier for RaTlsServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        end_entity
            .verify_quote(&self.config)
            .map_err(|e| rustls::Error::General(e.to_string()))?;

        Ok(ServerCertVerified::assertion())
    }
}

pub struct RaTlsClientCertResolver {
    cert: Option<Arc<rustls::sign::CertifiedKey>>,
}

impl Default for RaTlsClientCertResolver {
    fn default() -> Self {
        let builder = RaTlsCertificateBuilder::new().with_common_name("Client".to_string());
        let cert = builder.build().ok().map(Arc::new);
        Self { cert }
    }
}

impl RaTlsClientCertResolver {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

impl ResolvesClientCert for RaTlsClientCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.cert.clone()
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl RaTlsConfigBuilder<ClientConfig> for ClientConfig {
    fn from_ratls_config(config: RaTlsConfig) -> Self {
        Self::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(RaTlsServerCertVerifier::new(config)))
            .with_client_cert_resolver(Arc::new(RaTlsClientCertResolver::new()))
    }
}
