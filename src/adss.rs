use std::fmt::Debug;

use ctutils::CtEq;

use crate::errors::{
    ADSSError::{self, *},
    ADSSResult,
};

// Access structures and encodings
// We reserve all encodings starting with a 0 byte for the future
// We reserve all encodings where the first byte is greater than the second byte for the future
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThresholdAccess {
    threshold: u8,
    total: u8,
}

impl ThresholdAccess {
    pub fn new(threshold: u8, total: u8) -> ADSSResult<ThresholdAccess> {
        // TODO: Ensure 255 is allowed
        if threshold > 0 && threshold <= total {
            Ok(ThresholdAccess { threshold, total })
        } else {
            Err(InvalidThresholdAccess(threshold, total))
        }
    }

    pub fn serialize(&self) -> [u8; 2] {
        [self.threshold, self.total]
    }

    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    pub fn total(&self) -> u8 {
        self.total
    }
}

impl TryFrom<&[u8]> for ThresholdAccess {
    type Error = ADSSError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 2 {
            return Err(ThresholdAccessWrongLength(value.len()));
        }
        // TODO: Ensure 255 is allowed
        let threshold = value[0];
        let total = value[1];
        if threshold > 0 && threshold <= total {
            Ok(ThresholdAccess { threshold, total })
        } else {
            Err(InvalidThresholdAccess(threshold, total))
        }
    }
}

// Main share logic
#[derive(Clone, Eq)]
pub struct Share {
    pub(crate) id: u8,
    pub(crate) access_structure: ThresholdAccess,
    pub(crate) secret_part: Vec<u8>,
    pub(crate) public_part: Vec<u8>,
    pub(crate) tag: Vec<u8>,
}

impl Share {
    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn access_structure(&self) -> ThresholdAccess {
        self.access_structure
    }

    pub fn secret_part(&self) -> &[u8] {
        &self.secret_part
    }

    pub fn public_part(&self) -> &[u8] {
        &self.public_part
    }

    pub fn aad(&self) -> &[u8] {
        &self.tag
    }
}

impl Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("id", &self.id)
            .field("access_structure", &self.access_structure)
            .field("secret_part", &"[redacted]")
            .field("public_part", &self.public_part)
            .field("tag", &self.tag)
            .finish()
    }
}

impl PartialEq for Share {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id &&
        self.access_structure == other.access_structure && 
        self.public_part == other.public_part && 
        self.tag == other.tag &&
        self.secret_part.ct_eq(&other.secret_part).to_bool()
    }
}

pub(crate) trait ShareCollection {
    fn secret_parts(&self) -> ADSSResult<Vec<&[u8]>>;
    fn public_parts(&self) -> ADSSResult<Vec<&[u8]>>;
    fn ids(&self) -> ADSSResult<Vec<u8>>;
    fn access_structure(&self) -> ADSSResult<ThresholdAccess>;
    fn aad(&self) -> ADSSResult<&[u8]>;
    fn shares_len(&self) -> ADSSResult<u8>;
}

impl ShareCollection for &[Share] {
    fn secret_parts(&self) -> ADSSResult<Vec<&[u8]>> {
        self.shares_len()?;
        Ok(self.iter().map(|s| s.secret_part()).collect())
    }

    fn public_parts(&self) -> ADSSResult<Vec<&[u8]>> {
        self.shares_len()?;
        Ok(self.iter().map(|s| s.public_part()).collect())
    }

    fn ids(&self) -> ADSSResult<Vec<u8>> {
        self.shares_len()?;
        // TODO: Check for duplicate ids
        Ok(self.iter().map(|s| s.id()).collect())
    }

    fn access_structure(&self) -> ADSSResult<ThresholdAccess> {
        let count = self.shares_len()?;
        let result = self[0].access_structure();
        if self.iter().all(|a| a.access_structure() == result) {
            if count >= result.threshold() {
                Ok(result)
            } else {
                Err(BelowThreshold(count, result.threshold()))
            }
        } else {
            Err(AccessStructureMismatch)
        }
    }

    fn aad(&self) -> ADSSResult<&[u8]> {
        self.shares_len()?;
        let result = self[0].aad();
        if self.iter().all(|a| a.aad() == result) {
            Ok(result)
        } else {
            Err(AadMismatch)
        }
    }

    fn shares_len(&self) -> ADSSResult<u8> {
        let len = self.len();
        if len > 255 {
            Err(TooManyShares(len))
        } else if len == 0 {
            Err(NoShares)
        } else {
            Ok(len as u8)
        }
    }
}
