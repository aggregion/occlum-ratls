use std::{ error::Error, fmt::Display };

#[derive(Debug)]
pub enum RaTlsError {
    CertificateBuildError(String),
}

impl Display for RaTlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            RaTlsError::CertificateBuildError(ref message) =>
                write!(f, "CertificateBuildError: {}", message),
        }
    }
}

impl Error for RaTlsError {}