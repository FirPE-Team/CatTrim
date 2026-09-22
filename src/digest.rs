use std::fmt;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Digest {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= 2 && bytes[0] == 0 && bytes[1] == 0 {
            return None;
        }
        match bytes.len() {
            20 => Some(Self::Sha1(bytes.try_into().ok()?)),
            32 => Some(Self::Sha256(bytes.try_into().ok()?)),
            _ => None,
        }
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: &[u8] = match self {
            Self::Sha1(bytes) => bytes,
            Self::Sha256(bytes) => bytes,
        };
        for byte in bytes {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}
