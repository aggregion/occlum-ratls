use std::sync::Arc;

use rustls::{ client::{ ServerCertVerifier, ResolvesClientCert, ServerCertVerified } };
use x509_parser::{ prelude::X509CertificateParser, nom::Parser, oid_registry::Oid };
use crate::cert::{ CertificateBuilder, RaTlsCertificateBuilder, REPORT_OID };

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
        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        let (_, x509) = parser.parse(&end_entity.as_ref()).unwrap();

        let report_oid = Oid::from(&REPORT_OID).unwrap();

        if let Ok(Some(report)) = x509.get_extension_unique(&report_oid) {
            println!("Server dcap report: {:?}", report.value);
            // TODO: validate dcap report
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("No report extension".to_string()))
        }
    }
}

pub struct RaTlsClientCertResolver {
    cert_builder: Arc<dyn CertificateBuilder>,
}

impl Default for RaTlsClientCertResolver {
    fn default() -> Self {
        Self {
            cert_builder: Arc::new(
                RaTlsCertificateBuilder::new().with_common_name("Client".to_string())
            ),
        }
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