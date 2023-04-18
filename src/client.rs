use std::sync::Arc;

use rustls::client::{ ServerCertVerifier, ResolvesClientCert, ServerCertVerified };
use crate::cert::{ CertificateBuilder, RaTlsCertificateBuilder };

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
        _now: std::time::SystemTime
    ) -> Result<ServerCertVerified, rustls::Error> {
        println!("server cert: {:#?}", end_entity);
        Ok(ServerCertVerified::assertion())
    }
}

pub struct RaTlsClientCertResolver {
    cert_builder: Arc<dyn CertificateBuilder>,
}

impl Default for RaTlsClientCertResolver {
    fn default() -> Self {
        Self { cert_builder: Arc::new(RaTlsCertificateBuilder::new()) }
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
        _sigschemes: &[rustls::SignatureScheme]
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        self.cert_builder
            .build()
            .ok()
            .map(|x| Arc::new(x))
    }

    fn has_certs(&self) -> bool {
        true
    }
}