#[macro_use]
extern crate impl_ops;

use std::fmt::Debug;

use ctutils::CtEq;
use shake::digest::{array::Array, consts::{U8, U32}};

use crate::errors::{
    ADSSError::{self, *},
    ADSSResult,
};

mod ax;
mod errors;
#[cfg(feature = "ex")]
mod ex;
mod gf256;
mod oracles;
mod s1;

const SEC_PARAM_BYTES: usize = 32;
#[allow(non_camel_case_types)]
type SEC_PARAM_ARRAY_LEN = U32;
const COMPACT_SHARE_TYPE_BYTE: u8 = 1;
const COMMON_INFO_TYPE_BYTE: u8 = 2;
const EXPANDED_SHARE_TYPE_BYTE: u8 = 3;

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
    pub(crate) secret_part: [u8; SEC_PARAM_BYTES],
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
    pub(crate) secret_part: [u8; SEC_PARAM_BYTES],
}

impl From<&CompactShare> for [u8; 34] {
    fn from(value: &CompactShare) -> Self {
        let mut result = [0u8; 34];
        result[0] = COMPACT_SHARE_TYPE_BYTE;
        result[1] = value.id;
        result[2..].copy_from_slice(&value.secret_part);
        result
    }
}

impl TryFrom<&[u8]> for CompactShare {
    type Error = ADSSError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 34 {
            return Err(ADSSError::CompactShareWrongLength(value.len(), 34))
        }
        if value[0] != COMPACT_SHARE_TYPE_BYTE {
            return Err(ADSSError::WrongTypeByte(value[0], COMPACT_SHARE_TYPE_BYTE));
        }
        let id = value[1];
        if id == 0 {
            return Err(ADSSError::ZeroId);
        }
        let mut secret_part = [0u8; SEC_PARAM_BYTES];
        secret_part.copy_from_slice(&value[2..]);
        return Ok(CompactShare { id, secret_part })
    }
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
pub struct ShareCollectionImpl<I: ShareInfo> {
    pub(crate) shares: Vec<I>,
    pub(crate) access_structure: ThresholdAccess,
    pub(crate) public_part: Vec<u8>,
    pub(crate) tag: Vec<u8>,
}

pub type CompactShareCollection = ShareCollectionImpl<CompactShare>;

impl<I: ShareInfo> CommonInfo for ShareCollectionImpl<I> {
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

impl<I: ShareInfo> ShareCollection<I> for ShareCollectionImpl<I> {
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

    fn info(&self) -> ADSSResult<&[I]> {
        Ok(&self.shares)
    }
}

pub trait ShareCollection<S: ShareInfo>: Clone + CommonInfo {
    fn ids(&self) -> ADSSResult<Vec<u8>>;
    fn shares_len(&self) -> ADSSResult<u8>;
    fn info(&self) -> ADSSResult<&[S]>;

    fn expand(&self) -> ADSSResult<Vec<Share>> {
        let info = self.info()?;
        let mut result = vec![
            Share {
                id: 0,
                access_structure: self.access_structure()?,
                secret_part: [0u8; SEC_PARAM_BYTES],
                public_part: self.public_part()?.to_vec(),
                tag: self.aad()?.to_vec(),
            };
            info.len()
        ];
        for (dest, src) in result.iter_mut().zip(info) {
            dest.id = src.id();
            dest.secret_part.copy_from_slice(src.secret_part());
        }
        Ok(result)
    }

    fn compact(&self) -> ADSSResult<CompactShareCollection> {
        let shares: Vec<CompactShare> = self
            .info()?
            .iter()
            .map(|i| CompactShare {
                id: i.id(),
                secret_part: i.secret_part().try_into().unwrap(),
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

pub trait ShareInfo: Debug + PartialEq + Eq + Clone {
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

impl ShareCollection<Share> for Vec<Share> {
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

    fn info(&self) -> ADSSResult<&[Share]> {
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

impl ShareCollection<Share> for &[Share] {
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

    fn info(&self) -> ADSSResult<&[Share]> {
        Ok(self)
    }
}

pub fn share(
    access_structure: ThresholdAccess,
    message: &[u8],
    r: &Array<u8, SEC_PARAM_ARRAY_LEN>,
    aad: &[u8],
) -> ADSSResult<CompactShareCollection> {
    ax::share(access_structure, message, r, aad)
}

pub fn recover<I: ShareInfo, C: ShareCollection<I>>(
    shares: &C,
) -> ADSSResult<(Vec<u8>, [u8; SEC_PARAM_BYTES], Vec<u8>)> {
    ax::recover(shares)
}

#[cfg(feature = "ex")]
pub fn recover_error_correction<I: ShareInfo, C: ShareCollection<I>>(
    shares: &C,
) -> ADSSResult<(Vec<u8>, [u8; SEC_PARAM_BYTES], Vec<u8>)> {
    ex::recover(shares)
}

#[cfg(feature = "getrandom")]
pub fn share_randomized(
    access_structure: ThresholdAccess,
    message: &[u8],
    aad: &[u8],
) -> ADSSResult<CompactShareCollection> {
    use rand::{Rng, rngs::StdRng};

    let mut r = Array([0u8; SEC_PARAM_BYTES]);
    let mut rng: StdRng = rand::make_rng();
    rng.fill_bytes(&mut r);
    ax::share(access_structure, message, &r, aad)
}

// TODO: Define share serialization
// TODO: Test vectors

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "getrandom")]
    #[test]
    fn random_is_random() -> ADSSResult<()> {
        let message = b"something secret";
        let aad = b"Some aad value";
        let access_structure = ThresholdAccess::new(2, 2)?;

        let shares1 = share_randomized(access_structure, message, aad)?;
        let shares2 = share_randomized(access_structure, message, aad)?;

        assert_ne!(shares1.info()?[0], shares2.info()?[0]);
        assert_ne!(shares1.info()?[1], shares2.info()?[1]);

        let (recovered, _, _) = recover(&shares1)?;
        assert_eq!(message, recovered.as_slice());
        let (recovered, _, _) = recover(&shares2)?;
        assert_eq!(message, recovered.as_slice());
        Ok(())
    }

    #[test]
    fn random_deterministic() -> ADSSResult<()> {
        let message = b"something secret";
        let aad = b"Some aad value";
        let access_structure = ThresholdAccess::new(2, 2)?;
        let coins = Array([0u8; SEC_PARAM_BYTES]);

        let shares1 = share(access_structure, message, &coins, aad)?;
        let shares2 = share(access_structure, message, &coins, aad)?;

        assert_eq!(shares1, shares2);
        Ok(())
    }
}