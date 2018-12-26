#[derive(Clone, Copy)]
pub enum Error {
    InvalidChar,
    InvalidLength(usize),
}

impl ::std::fmt::Debug for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            Error::InvalidLength(len) => write!(f, "Invalid input length {}", len),
            Error::InvalidChar => write!(f, "Invalid character"),
        }
    }
}

impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Debug::fmt(&self, f)
    }
}

impl ::std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::InvalidChar => "invalid character",
            Error::InvalidLength(_) => "invalid length",
        }
    }
}
