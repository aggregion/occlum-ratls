use std::{ time::SystemTime, sync::Arc };
use log::warn;
use x509_parser::nom::Parser;
use x509_parser::prelude::X509CertificateParser;

use rustls::{
    server::{ ClientCertVerifier, ClientCertVerified, ResolvesServerCert },
    Certificate,
    Error,
    DistinguishedNames,
};

use crate::cert::{ CertificateBuilder, RaTlsCertificateBuilder };

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

        let subject = x509.subject();
        let issuer = x509.issuer();

        println!("X.509 Subject: {}", subject);
        println!("X.509 Issuer: {}", issuer);
        println!("X.509 Extensions: {:#?}", x509.extensions());

        let orgs: Vec<String> = subject
            .iter_organization()
            .map(|x| x.attr_value().as_string().unwrap())
            .collect();

        println!("{:?}", orgs);
        if orgs[0] != "Scontain".to_string() {
            warn!("Access denied for client with orgs: {:?}", orgs);
            return Err(Error::InvalidCertificateData("Bad org".to_string()));
        }

        Ok(ClientCertVerified::assertion())
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