use std::sync::Arc;

use log::error;
use rustls::{ Certificate, PrivateKey, sign::RsaSigningKey };
use openssl::{
    rsa::Rsa,
    pkey::{ PKey, Private, Public },
    x509::{ X509Builder, X509NameBuilder, X509Name },
    error::ErrorStack,
    asn1::Asn1Time,
};

use crate::error::RaTlsError;

pub trait CertificateBuilder: Send + Sync {
    fn build(&self) -> Result<rustls::sign::CertifiedKey, RaTlsError>;
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

impl RaTlsCertificateBuilder {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn with_common_name(&mut self, cn: String) -> &mut Self {
        self.common_name = cn;
        self
    }

    // Generate private and public keys by RSA
    fn get_keys(&self) -> Result<(PKey<Private>, PKey<Public>), ErrorStack> {
        let rsa = Rsa::generate(2048)?;

        let public = PKey::public_key_from_der(&rsa.public_key_to_der()?)?;
        let private = PKey::private_key_from_der(&rsa.private_key_to_der()?)?;

        return Ok((private, public));
    }

    fn get_x509_name(&self) -> Result<X509Name, ErrorStack> {
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", self.common_name.as_str())?;
        name_builder.append_entry_by_text("C", "US")?;
        name_builder.append_entry_by_text("O", "Aggregion")?;
        Ok(name_builder.build())
    }

    fn build_internal(&self) -> Result<RaTlsCertifiedKey, ErrorStack> {
        let (private_key, public_key) = self.get_keys()?;
        let name = self.get_x509_name()?;

        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(356)?;

        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&public_key)?;

        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;

        // let nid = Nid::create("1.2.840.113741.1", "RA-TLS", "RA-TLS Ext")?;
        // let value = format!("ASN1:UTF8String:{}", "message");
        // builder.append_extension(X509Extension::new_nid(None, None, nid, &value)?)?;

        builder.sign(&private_key, openssl::hash::MessageDigest::sha256())?;

        let x509 = builder.build();

        Ok(RaTlsCertifiedKey {
            cert_der: x509.to_der()?,
            key_der: private_key.private_key_to_der()?,
        })
    }
}

impl CertificateBuilder for RaTlsCertificateBuilder {
    fn build(&self) -> Result<rustls::sign::CertifiedKey, RaTlsError> {
        self.build_internal()
            .map(|x| {
                let sign_key = RsaSigningKey::new(&PrivateKey(x.key_der)).unwrap();
                rustls::sign::CertifiedKey::new(vec![Certificate(x.cert_der)], Arc::new(sign_key))
            })
            .map_err(|e| {
                let err = RaTlsError::CertificateBuildError(format!("{}", e));
                error!("{}", err);
                err
            })
    }
}