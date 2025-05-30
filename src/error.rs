#[derive(Debug, thiserror::Error)]
pub enum CtLogError {
    #[error("Parse URL error: {0}")]
    ParseUrlError(#[from] url::ParseError),

    #[error("Binary error: {0}")]
    BinaryError(#[from] BinaryParsingError),

    #[error("Base64 error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}

#[derive(Debug, thiserror::Error)]
pub enum BinaryParsingError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Insufficient data")]
    InsufficientData,

    #[error("Invalid sequence: {0}")]
    InvalidSequence(String),

    #[error("X509 error: {0}")]
    X509Error(String),
}
