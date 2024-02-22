use std::error::Error;

#[cfg(feature = "occlum")]
use crate::utils::hash_sha512;
use crate::{error::RaTlsError, RaTlsConfig};
use log::error;

#[cfg(feature = "occlum")]
use occlum_sgx::SGXQuote;
use rustls::{
    sign::{any_supported_type, CertifiedKey},
    Certificate, PrivateKey,
};

use rcgen::{
    Certificate as GenCertificate, CertificateParams, CustomExtension, DistinguishedName, KeyPair,
};

#[cfg(feature = "occlum")]
use x509_parser::{nom::Parser, oid_registry::Oid, prelude::X509CertificateParser, public_key};

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
        Self { common_name: cn }
    }

    fn build_internal(&self) -> Result<RaTlsCertifiedKey, Box<dyn Error>> {
        let mut distinguished_name = DistinguishedName::new();

        distinguished_name.push(rcgen::DnType::CommonName, self.common_name.clone());
        distinguished_name.push(rcgen::DnType::CountryName, "US");
        distinguished_name.push(rcgen::DnType::OrganizationName, "Aggregion");

        let mut params = CertificateParams::default();
        let key_pair = KeyPair::generate(params.alg)?;

        let quote = self.get_quote(&key_pair)?;

        params.key_pair = Some(key_pair);
        params.distinguished_name = distinguished_name;

        params.custom_extensions = vec![CustomExtension::from_oid_content(&REPORT_OID, quote)];

        let crt = GenCertificate::from_params(params)?;

        Ok(RaTlsCertifiedKey {
            cert_der: crt.serialize_der()?,
            key_der: crt.serialize_private_key_der(),
        })
    }

    #[cfg(not(feature = "occlum"))]
    fn get_quote(&self, _: &KeyPair) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok([0u8; 32].to_vec())
    }

    #[cfg(feature = "occlum")]
    fn get_quote(&self, key_pair: &KeyPair) -> Result<Vec<u8>, Box<dyn Error>> {
        let public_key = key_pair.public_key_raw().to_vec();
        let report_data = hash_sha512(public_key);
        let quote = SGXQuote::from_report_data(&report_data)?;

        Ok(quote.as_slice().to_vec())
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
    #[cfg(not(feature = "occlum"))]
    fn verify_quote(&self, _: &RaTlsConfig) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    #[cfg(feature = "occlum")]
    fn verify_quote(&self, config: &RaTlsConfig) -> Result<(), Box<dyn Error>> {
        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        let (_, x509) = parser.parse(self.as_ref()).unwrap();

        let report_oid = Oid::from(&REPORT_OID).unwrap();

        if let Ok(Some(report)) = x509.get_extension_unique(&report_oid) {
            let quote = SGXQuote::from_slice(report.value)?;

            quote.verify()?;

            let public_key = x509.public_key().parsed()?;
            let public_key = match public_key {
                public_key::PublicKey::EC(key) => key.data().to_vec(),
                _ => return Err("Unexpected public key type".into()),
            };

            let report_data = &*quote.report_data();

            if hash_sha512(public_key) != report_data {
                return Err("Invalid quote report data".into());
            }

            config.is_allowed_quote(&quote)?;

            Ok(())
        } else {
            Err("Not found quote extension".into())
        }
    }
}
