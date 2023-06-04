use std::error::Error;

use crate::{error::RaTlsError, prelude::RaTlsConfig, utils::hash_sha512};
use log::error;
use occlum_sgx::SGXQuote;
use rustls::{
    sign::{any_supported_type, CertifiedKey},
    Certificate, PrivateKey,
};

use rcgen::{
    Certificate as GenCertificate, CertificateParams, CustomExtension, DistinguishedName, KeyPair,
};
use x509_parser::{nom::Parser, oid_registry::Oid, prelude::X509CertificateParser};

pub trait CertificateBuilder: Send + Sync {
    fn build(&self) -> Result<CertifiedKey, RaTlsError>;
}

struct RaTlsCertifiedKey {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

pub struct RaTlsCertificateBuilder {
    common_name: String,
}

impl Default for RaTlsCertificateBuilder {
    fn default() -> Self {
        Self {
            common_name: "RATLS".to_string(),
        }
    }
}

pub const REPORT_OID: [u64; 5] = [1, 2, 840, 113741, 1];

impl RaTlsCertificateBuilder {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn with_common_name(self, cn: String) -> Self {
        Self {
            common_name: cn,
            ..self
        }
    }

    fn build_internal(&self) -> Result<RaTlsCertifiedKey, Box<dyn Error>> {
        let mut distinguished_name = DistinguishedName::new();

        distinguished_name.push(rcgen::DnType::CommonName, self.common_name.clone());
        distinguished_name.push(rcgen::DnType::CountryName, "US");
        distinguished_name.push(rcgen::DnType::OrganizationName, "Aggregion");

        let mut params = CertificateParams::default();
        let key_pair = KeyPair::generate(&params.alg)?;
        let public_key = key_pair.public_key_raw().to_vec();

        params.key_pair = Some(key_pair);
        params.distinguished_name = distinguished_name;

        let report_data = hash_sha512(public_key);
        let quote = SGXQuote::from_report_data(&report_data)?;

        params.custom_extensions = vec![CustomExtension::from_oid_content(
            &REPORT_OID,
            quote.as_slice().to_vec(),
        )];

        let crt = GenCertificate::from_params(params)?;

        return Ok(RaTlsCertifiedKey {
            cert_der: crt.serialize_der()?,
            key_der: crt.serialize_private_key_der(),
        });
    }
}

impl CertificateBuilder for RaTlsCertificateBuilder {
    fn build(&self) -> Result<CertifiedKey, RaTlsError> {
        self.build_internal()
            .map(|k| {
                let sign_key = any_supported_type(&PrivateKey(k.key_der)).unwrap();

                CertifiedKey::new(vec![Certificate(k.cert_der)], sign_key)
            })
            .map_err(|e| {
                let err = RaTlsError::CertificateBuildError(e.to_string());
                error!("{}", err);
                err
            })
    }
}

pub trait RaTlsCertificate {
    fn verify_quote(&self, config: &RaTlsConfig) -> Result<(), Box<dyn Error>>;
}

impl RaTlsCertificate for rustls::Certificate {
    fn verify_quote(&self, config: &RaTlsConfig) -> Result<(), Box<dyn Error>> {
        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        let (_, x509) = parser.parse(&self.as_ref()).unwrap();

        let report_oid = Oid::from(&REPORT_OID).unwrap();

        if let Ok(Some(report)) = x509.get_extension_unique(&report_oid) {
            let public_key = x509.public_key().raw.to_vec();
            let quote = SGXQuote::from_slice(report.value)?;

            quote.verify()?;

            let report_data = &*quote.report_data();

            if hash_sha512(public_key) != report_data {
                return Err("Invalid quote report".into());
            }

            config.verify_quote(&quote)?;

            Ok(())
        } else {
            Err("No report extension".into())
        }
    }
}
