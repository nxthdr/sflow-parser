//! Parser error types

use std::fmt;
use std::io;

/// Parser error type
#[derive(Debug)]
pub enum ParseError {
    /// I/O error
    Io(io::Error),
    /// Invalid data format
    InvalidData(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "I/O error: {}", e),
            ParseError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<io::Error> for ParseError {
    fn from(err: io::Error) -> Self {
        ParseError::Io(err)
    }
}

impl From<std::string::FromUtf8Error> for ParseError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        ParseError::InvalidData(format!("Invalid UTF-8 string: {}", err))
    }
}

/// Result type for parser operations
pub type Result<T> = std::result::Result<T, ParseError>;
