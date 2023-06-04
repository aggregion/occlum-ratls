use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub enum RaTlsError {
    CertificateBuildError(String),
    QuoteVerifyError(String),
}

impl Display for RaTlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            RaTlsError::CertificateBuildError(ref message) => {
                write!(f, "CertificateBuildError: {}", message)
            }
            RaTlsError::QuoteVerifyError(ref message) => write!(f, "QuoteVerifyError: {}", message),
        }
    }
}

impl Error for RaTlsError {}
