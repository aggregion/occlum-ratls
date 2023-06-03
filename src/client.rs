use std::sync::Arc;

use crate::cert::{CertificateBuilder, RaTlsCertificate, RaTlsCertificateBuilder};
use rustls::client::{ResolvesClientCert, ServerCertVerified, ServerCertVerifier};

pub struct RaTlsServerCertVerifier {}

impl RaTlsServerCertVerifier {
    pub fn new() -> Self {
        Self {}
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
        let quote = end_entity.get_quote()?;

        quote
            .verify()
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
        let cert = builder.build().ok().map(|x| Arc::new(x));
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
