use std::{ error::Error };

use log::error;
use rustls::{ Certificate, PrivateKey, sign::{ CertifiedKey, any_supported_type } };
use crate::error::RaTlsError;

use rcgen::{ Certificate as GenCertificate, CertificateParams, DistinguishedName, CustomExtension };

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
        Self { common_name: "RATLS".to_string() }
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

        params.distinguished_name = distinguished_name;

        // TODO: replace vec![0;500] it with dcap report
        params.custom_extensions = vec![
            CustomExtension::from_oid_content(&REPORT_OID, vec![0;500])
        ];

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