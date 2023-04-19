use std::{ time::SystemTime, sync::Arc };
use x509_parser::oid_registry::Oid;
use x509_parser::{ nom::Parser };
use x509_parser::prelude::X509CertificateParser;

use rustls::{
    server::{ ClientCertVerifier, ClientCertVerified, ResolvesServerCert },
    Certificate,
    Error,
    DistinguishedNames,
};

use crate::cert::{ CertificateBuilder, RaTlsCertificateBuilder, REPORT_OID };

pub struct RaTlsClientCertVerifier {}

impl RaTlsClientCertVerifier {
    pub fn new() -> Self {
        Self {}
    }
}

impl ClientCertVerifier for RaTlsClientCertVerifier {
    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _now: SystemTime
    ) -> Result<ClientCertVerified, Error> {
        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        let (_, x509) = parser.parse(&end_entity.as_ref()).unwrap();
        let report_oid = Oid::from(&REPORT_OID).unwrap();

        if let Ok(Some(report)) = x509.get_extension_unique(&report_oid) {
            println!("Client dcap report: {:?}", report.value);
            // TODO: validate dcap report
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General("No report extension".to_string()))
        }
    }

    fn client_auth_root_subjects(&self) -> Option<rustls::DistinguishedNames> {
        Some(DistinguishedNames::new())
    }
}

pub struct RaTlsServerCertResolver {
    cert_builder: Arc<dyn CertificateBuilder>,
}

impl Default for RaTlsServerCertResolver {
    fn default() -> Self {
        Self { cert_builder: Arc::new(RaTlsCertificateBuilder::new()) }
    }
}

impl RaTlsServerCertResolver {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn with_cert_builder(self, cb: Arc<dyn CertificateBuilder>) -> Self {
        Self {
            cert_builder: cb,
            ..self
        }
    }
}

impl ResolvesServerCert for RaTlsServerCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        self.cert_builder
            .build()
            .ok()
            .map(|x| Arc::new(x))
    }
}