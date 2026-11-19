#[macro_use]
extern crate impl_ops;

use std::{collections::HashSet, fmt::Debug};

use ctutils::CtEq;
use shake::digest::{array::Array, consts::U32};

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
#[cfg(test)]
mod kats;

const SEC_PARAM_BYTES: usize = 32;
#[allow(non_camel_case_types)]
type SEC_PARAM_ARRAY_LEN = U32;
const COMPACT_SHARE_TYPE_BYTE: u8 = 1;
const COMMON_INFO_TYPE_BYTE: u8 = 2;
const EXPANDED_SHARE_TYPE_BYTE: u8 = 3;
const COMPACT_SHARE_LENGTH: usize = 34;

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

    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    pub fn total(&self) -> u8 {
        self.total
    }

    fn serialize(&self) -> [u8; 2] {
        [self.threshold, self.total]
    }
}

impl From<ThresholdAccess> for [u8; 2]
 {
    fn from(value: ThresholdAccess) -> Self {
        value.serialize()
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

#[derive(Clone, Eq)]
pub struct CompactShare {
    pub(crate) id: u8,
    pub(crate) secret_part: [u8; SEC_PARAM_BYTES],
}

impl From<&CompactShare> for [u8; COMPACT_SHARE_LENGTH] {
    fn from(value: &CompactShare) -> Self {
        let mut result = [0u8; COMPACT_SHARE_LENGTH];
        result[0] = COMPACT_SHARE_TYPE_BYTE;
        result[1] = value.id;
        result[2..].copy_from_slice(&value.secret_part);
        result
    }
}

impl TryFrom<&[u8]> for CompactShare {
    type Error = ADSSError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != COMPACT_SHARE_LENGTH {
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
        Ok(CompactShare { id, secret_part })
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
pub struct CommonInfo {
    access_structure: ThresholdAccess,
    public_part: Vec<u8>,
    aad: Vec<u8>
}

impl CommonInfo {
    pub fn access_structure(&self) -> ThresholdAccess {
        self.access_structure
    }

    pub fn public_part(&self) -> &[u8] {
        &self.public_part
    }

    pub fn aad(&self) -> &[u8] {
        &self.aad
    }
}

impl CommonInfo {
    pub fn new(access_structure: ThresholdAccess, public_part: &[u8], aad: &[u8]) -> ADSSResult<CommonInfo> {
        if public_part.len() > u32::MAX as usize || aad.len() > u32::MAX as usize {
            return Err(ADSSError::DataOverflow);
        }
        Ok(CommonInfo {
            access_structure, public_part: public_part.to_vec(), aad: aad.to_vec()
        })
    }
}

impl From<&CommonInfo> for Vec<u8> {
    fn from(value: &CommonInfo) -> Self {
        let mut result = vec![COMMON_INFO_TYPE_BYTE];
        result.extend_from_slice(&std::convert::Into::<[u8;2]>::into(value.access_structure));
        result.extend_from_slice(&(value.public_part.len() as u32).to_be_bytes());
        result.extend_from_slice(&value.public_part);
        result.extend_from_slice(&(value.aad.len() as u32).to_be_bytes());
        result.extend_from_slice(&value.aad);
        result
    }
}

impl TryFrom<&[u8]> for CommonInfo {
    type Error = ADSSError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 9 {
            return Err(DataOverflow);
        }
        let mut offset = 0;
        if value[offset] != COMMON_INFO_TYPE_BYTE {
            return Err(ADSSError::WrongTypeByte(value[0], COMMON_INFO_TYPE_BYTE))
        }
        offset += 1;
        let access_structure : ThresholdAccess = value[offset..offset+2].try_into()?;
        offset += 2;

        let public_part_len = u32::from_be_bytes(value[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;
        if value.len() < offset + 4 + public_part_len {
            return Err(DataOverflow);
        }
        let public_part = value[offset..offset+public_part_len].to_vec();
        offset += public_part_len;
        let aad_len = u32::from_be_bytes(value[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;
        if value.len() != offset + aad_len {
            return Err(DataOverflow);
        }
        let aad = value[offset..].to_vec();
        Ok(CommonInfo { access_structure, public_part, aad })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedShare {
    share: CompactShare,
    common: CommonInfo
}

impl ExpandedShare {
    pub fn new(share: CompactShare, common: CommonInfo) -> ADSSResult<ExpandedShare> {
        Ok(ExpandedShare{share, common})
    }
}

impl From<&ExpandedShare> for Vec<u8> {
    fn from(value: &ExpandedShare) -> Self {
        let mut result = vec![EXPANDED_SHARE_TYPE_BYTE];
        let share: [u8; COMPACT_SHARE_LENGTH] = (&value.share).into();
        result.extend_from_slice(&share);
        let common: Vec<u8> = (&value.common).into();
        result.extend_from_slice(&common);
        result
    }
}

impl TryFrom<&[u8]> for ExpandedShare {
    type Error = ADSSError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 36 {
            return Err(ADSSError::DataUnderflow);
        }
        if value[0] != EXPANDED_SHARE_TYPE_BYTE {
            return Err(WrongTypeByte(value[0], EXPANDED_SHARE_TYPE_BYTE));
        }
        let share : CompactShare = value[1..COMPACT_SHARE_LENGTH+1].try_into()?;
        let common : CommonInfo = value[1+COMPACT_SHARE_LENGTH..].try_into()?;
        Ok(ExpandedShare{ share, common })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryInput {
    shares: Vec<CompactShare>,
    common: CommonInfo
}

impl RecoveryInput {
    pub fn new(shares: Vec<CompactShare>, common: CommonInfo) -> ADSSResult<RecoveryInput> {
        if shares.is_empty() {
            return Err(ADSSError::NoShares);
        }
        let mut id_set = HashSet::new();
        let mut expected_len = None;
        for s in &shares {
            if s.id() > common.access_structure().total() {
                return Err(ADSSError::NoShares);
            }
            if !id_set.insert(s.id()) {
                return Err(ADSSError::IncompatibleShares);
            }
            if let Some(length) = expected_len {
                if s.secret_part.len() != length {
                    return Err(ADSSError::IncompatibleShares)
                }
            } else {
                expected_len = Some(s.secret_part.len());
            }
        }
        Ok(RecoveryInput { shares, common })
    }

    pub fn from_expanded(shares: &[ExpandedShare]) -> ADSSResult<RecoveryInput> {
        todo!()
    }

    pub fn shares(&self) -> &[CompactShare] {
        &self.shares
    }

    pub fn common(&self) -> &CommonInfo {
        &self.common
    }
}


pub trait ShareInfo: Debug + PartialEq + Eq + Clone {
    fn id(&self) -> u8;

    fn secret_part(&self) -> &[u8];
}

pub fn share_secret(
    access_structure: ThresholdAccess,
    message: &[u8],
    r: &Array<u8, SEC_PARAM_ARRAY_LEN>,
    aad: &[u8],
) -> ADSSResult<RecoveryInput> {
    ax::share(access_structure, message, r, aad)
}

pub fn recover_secret(shares: &RecoveryInput) -> ADSSResult<(Vec<u8>, [u8; SEC_PARAM_BYTES])> {
    ax::recover(shares)
}

#[cfg(feature = "ex")]
pub fn recover_from_subset(shares: &RecoveryInput) -> ADSSResult<(Vec<u8>, [u8; SEC_PARAM_BYTES], Vec<u8>)> {
    ex::recover(shares)
}

#[cfg(feature = "getrandom")]
pub fn share_randomized(
    access_structure: ThresholdAccess,
    message: &[u8],
    aad: &[u8],
) -> ADSSResult<RecoveryInput> {
    use rand::{Rng, rngs::StdRng};

    let mut r = Array([0u8; SEC_PARAM_BYTES]);
    let mut rng: StdRng = rand::make_rng();
    rng.fill_bytes(&mut r);
    ax::share(access_structure, message, &r, aad)
}

// TODO: Test vectors

trait ShareSlice {
    fn ids(&self) -> Vec<u8>;
}

impl ShareSlice for &[CompactShare] {
    fn ids(&self) -> Vec<u8> {
        self.iter().map(|s| s.id).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "getrandom")]
    #[test]
    fn random_is_random() -> ADSSResult<()> {
        let message = b"something secret";
        let aad = b"Some aad value";
        let access_structure = ThresholdAccess::new(2, 2)?;

        let input1 = share_randomized(access_structure, message, aad)?;
        let input2 = share_randomized(access_structure, message, aad)?;

        assert_ne!(input1.shares()[0], input2.shares()[0]);
        assert_ne!(input1.shares()[1], input2.shares()[1]);

        let (recovered, _) = recover_secret(&input1)?;
        assert_eq!(message, recovered.as_slice());
        let (recovered, _) = recover_secret(&input2)?;
        assert_eq!(message, recovered.as_slice());
        Ok(())
    }

    #[test]
    fn random_deterministic() -> ADSSResult<()> {
        let message = b"something secret";
        let aad = b"Some aad value";
        let access_structure = ThresholdAccess::new(2, 2)?;
        let coins = Array([0u8; SEC_PARAM_BYTES]);

        let shares1 = share_secret(access_structure, message, &coins, aad)?;
        let shares2 = share_secret(access_structure, message, &coins, aad)?;

        assert_eq!(shares1, shares2);
        Ok(())
    }
}