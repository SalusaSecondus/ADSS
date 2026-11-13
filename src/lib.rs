#[macro_use]
extern crate impl_ops;

use std::fmt::Debug;

use ctutils::CtEq;

use crate::errors::{
    ADSSError::{self, *},
    ADSSResult,
};

mod ax;
pub mod errors;
mod gf256;
mod oracles;
mod s1;

const SEC_PARAM_BYTES: usize = 32;

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

// TODO: Have a compact share version which only has (id, secret_part)
// Let that be the default internal representation and permit it to be expanded to the full version if needed

// Main share logic
#[derive(Clone, Eq)]
pub struct Share {
    pub(crate) id: u8,
    pub(crate) access_structure: ThresholdAccess,
    pub(crate) secret_part: Vec<u8>,
    pub(crate) public_part: Vec<u8>,
    pub(crate) tag: Vec<u8>,
}

impl CommonInfo for Share {
    fn access_structure(&self) -> ADSSResult<ThresholdAccess> {
        Ok(self.access_structure)
    }

    fn public_part(&self) -> ADSSResult<&[u8]> {
        Ok(&self.public_part)
    }

    fn aad(&self) -> ADSSResult<&[u8]> {
        Ok(&self.tag)
    }
}

impl ShareInfo for Share {
    fn id(&self) -> u8 {
        self.id
    }

    fn secret_part(&self) -> &[u8] {
        &self.secret_part
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
        self.id == other.id
            && self.access_structure == other.access_structure
            && self.public_part == other.public_part
            && self.tag == other.tag
            && self.secret_part.ct_eq(&other.secret_part).to_bool()
    }
}

#[derive(Clone, Eq)]
pub struct CompactShare {
    pub(crate) id: u8,
    pub(crate) secret_part: Vec<u8>,
}

impl ShareInfo for CompactShare {
    fn id(&self) -> u8 {
        self.id
    }

    fn secret_part(&self) -> &[u8] {
        &self.secret_part
    }
}

impl PartialEq for CompactShare {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.secret_part.ct_eq(&other.secret_part).to_bool()
    }
}

impl Debug for CompactShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompactShare")
            .field("id", &self.id)
            .field("secret_part", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactShareCollection {
    pub(crate) shares: Vec<CompactShare>,
    pub(crate) access_structure: ThresholdAccess,
    pub(crate) public_part: Vec<u8>,
    pub(crate) tag: Vec<u8>,
}

impl CommonInfo for CompactShareCollection {
    fn public_part(&self) -> ADSSResult<&[u8]> {
        self.shares_len()?;
        Ok(&self.public_part)
    }

    fn access_structure(&self) -> ADSSResult<ThresholdAccess> {
        self.shares_len()?;
        Ok(self.access_structure)
    }

    fn aad(&self) -> ADSSResult<&[u8]> {
        self.shares_len()?;
        Ok(&self.tag)
    }
}

impl ShareCollection for CompactShareCollection {
    fn ids(&self) -> ADSSResult<Vec<u8>> {
        self.shares_len()?;
        // TODO: Check for duplicate ids
        Ok(self.shares.iter().map(|s| s.id()).collect())
    }

    fn shares_len(&self) -> ADSSResult<u8> {
        let len = self.shares.len();
        if len > 255 {
            Err(TooManyShares(len))
        } else if len == 0 {
            Err(NoShares)
        } else {
            Ok(len as u8)
        }
    }

    fn info(&self) -> ADSSResult<&[impl ShareInfo]> {
        Ok(&self.shares)
    }
}

pub(crate) trait ShareCollection: Clone + CommonInfo {
    fn ids(&self) -> ADSSResult<Vec<u8>>;
    fn shares_len(&self) -> ADSSResult<u8>;
    fn info(&self) -> ADSSResult<&[impl ShareInfo]>;

    fn expand(&self) -> ADSSResult<Vec<Share>> {
        let info = self.info()?;
        let mut result = vec![
            Share {
                id: 0,
                access_structure: self.access_structure()?,
                secret_part: vec![],
                public_part: self.public_part()?.to_vec(),
                tag: self.aad()?.to_vec(),
            };
            info.len()
        ];
        for (dest, src) in result.iter_mut().zip(info) {
            dest.id = src.id();
            dest.secret_part.extend_from_slice(src.secret_part());
        }
        Ok(result)
    }

    fn compact(&self) -> ADSSResult<CompactShareCollection> {
        let shares: Vec<CompactShare> = self
            .info()?
            .iter()
            .map(|i| CompactShare {
                id: i.id(),
                secret_part: i.secret_part().to_vec(),
            })
            .collect();
        Ok(CompactShareCollection {
            shares,
            access_structure: self.access_structure()?,
            public_part: self.public_part()?.to_vec(),
            tag: self.aad()?.to_vec(),
        })
    }
}

pub trait ShareInfo: Debug + PartialEq + Eq {
    fn id(&self) -> u8;

    fn secret_part(&self) -> &[u8];
}

pub trait CommonInfo: Debug + PartialEq + Eq {
    fn public_part(&self) -> ADSSResult<&[u8]>;
    fn access_structure(&self) -> ADSSResult<ThresholdAccess>;
    fn aad(&self) -> ADSSResult<&[u8]>;
}

impl CommonInfo for Vec<Share> {
    fn public_part(&self) -> ADSSResult<&[u8]> {
        self.shares_len()?;
        let result = self[0].public_part()?;
        if self
            .iter()
            .all(|a| a.public_part().is_ok_and(|a| a == result))
        {
            Ok(result)
        } else {
            Err(AadMismatch)
        }
    }

    fn access_structure(&self) -> ADSSResult<ThresholdAccess> {
        let count = self.shares_len()?;
        let result = self[0].access_structure()?;
        if self
            .iter()
            .all(|a| a.access_structure().is_ok_and(|a| a == result))
        {
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
        let result = self[0].aad()?;
        if self.iter().all(|a| a.aad().is_ok_and(|a| a == result)) {
            Ok(result)
        } else {
            Err(AadMismatch)
        }
    }
}

impl ShareCollection for Vec<Share> {
    fn ids(&self) -> ADSSResult<Vec<u8>> {
        self.shares_len()?;
        // TODO: Check for duplicate ids
        Ok(self.iter().map(|s| s.id()).collect())
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

    fn info(&self) -> ADSSResult<&[impl ShareInfo]> {
        Ok(self)
    }
}

impl CommonInfo for &[Share] {
    fn public_part(&self) -> ADSSResult<&[u8]> {
        self.shares_len()?;
        let result = self[0].public_part()?;
        if self
            .iter()
            .all(|a| a.public_part().is_ok_and(|a| a == result))
        {
            Ok(result)
        } else {
            Err(AadMismatch)
        }
    }

    fn access_structure(&self) -> ADSSResult<ThresholdAccess> {
        let count = self.shares_len()?;
        let result = self[0].access_structure()?;
        if self
            .iter()
            .all(|a| a.access_structure().is_ok_and(|a| a == result))
        {
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
        let result = self[0].aad()?;
        if self.iter().all(|a| a.aad().is_ok_and(|a| a == result)) {
            Ok(result)
        } else {
            Err(AadMismatch)
        }
    }
}

impl ShareCollection for &[Share] {
    fn ids(&self) -> ADSSResult<Vec<u8>> {
        self.shares_len()?;
        // TODO: Check for duplicate ids
        Ok(self.iter().map(|s| s.id()).collect())
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

    fn info(&self) -> ADSSResult<&[impl ShareInfo]> {
        Ok(self)
    }
}
