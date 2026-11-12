use thiserror::Error;

use crate::errors::ADSSError::{NoShares, TooManyShares};

#[derive(Error, Debug)]
pub enum ADSSError {
    #[error("no shares")]
    NoShares,
    #[error("too many shares: {0}")]
    TooManyShares(usize),
    #[error("not all shares have the same AAD")]
    AadMismatch,
    #[error("the data in a share is incompatible with the algorithm")]
    UnsupportedShareType,
    #[error("insufficient shares to reconstruct. Had {0} but needed {1}")]
    BelowThreshold(u8, u8),
    #[error("not all shares have the same access structure")]
    AccessStructureMismatch,
    #[error("Encoding for ThresholdAccess is of wrong length: {0}")]
    ThresholdAccessWrongLength(usize),
    #[error("Invalid encoding for ThresholdAccess: {0}, {1}")]
    InvalidThresholdAccess(u8, u8),
    #[error("invalid coin length. Had {0} but needed {0}")]
    InvalidCoinLength(usize, usize),
    #[error("reconstruction failed integrity check")]
    IntegrityError
}

pub type ADSSResult<T> = Result<T, ADSSError>;