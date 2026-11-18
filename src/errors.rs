use thiserror::Error;

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
    #[error("invalid coin length. Had {0} but needed {1}")]
    InvalidCoinLength(usize, usize),
    #[error("reconstruction failed integrity check")]
    IntegrityError,
    #[error("CompactShare wrong length. Had {0} but needed {1}")]
    CompactShareWrongLength(usize, usize),
    #[error("serialized data has wrong type byte. Had {0} but needed {1}")]
    WrongTypeByte(u8, u8),
    #[error("id must not have a value of zero")]
    ZeroId,
    #[error("data too large")]
    DataOverflow,
    #[error("insufficient data")]
    DataUnderflow,
    #[error("incompatible shares provided")]
    IncompatibleShares,
}

pub type ADSSResult<T> = Result<T, ADSSError>;
