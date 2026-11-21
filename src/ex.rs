use std::collections::HashMap;

use ctutils::CtEq;
use itertools::Itertools;

use crate::{
    CompactShare, RecoveryInput, SEC_PARAM_BYTES, ShareInfo, ShareSlice, ThresholdAccess, ax, errors::{ADSSError::IntegrityError, ADSSResult},
};

pub(crate) fn recover(input: &RecoveryInput) -> ADSSResult<(Vec<u8>, [u8; SEC_PARAM_BYTES], Vec<u8>)> {
    let mut result: Option<(Vec<u8>, [u8; SEC_PARAM_BYTES])> = None;
    let mut result_shares : Option<HashMap<u8, CompactShare>> = None;
    let shares = input.shares();
    let common = input.common();
    let mut inner = RecoveryInput { shares: vec![], common: common.clone() };

    for attempt in plausibleCombinations(common.access_structure(), shares)? {
        // We skip proper subsets
        if let Some(prior_shares) = &result_shares && prior_shares.contains_all_refs(&attempt) {
                continue;
        }
        let cloned : Vec<CompactShare> = attempt.iter().cloned().cloned().collect();
        inner.shares = cloned;

        let partial_result = ax::recover(&inner);
        if let Ok(candidate) = partial_result {
            if let Some(prior) = &result {
                if !compatibleResults(prior, &candidate)? {
                    return Err(IntegrityError);
                }
            } else {
                result_shares = Some(inner.shares().as_map()?);
                result = Some(candidate);
            }
        }
    }

    result.map(|c| (c.0, c.1, result_shares.unwrap().ids())).ok_or(IntegrityError)
}

fn compatibleResults(
    first: &(Vec<u8>, [u8; SEC_PARAM_BYTES]),
    second: &(Vec<u8>, [u8; SEC_PARAM_BYTES]),
) -> ADSSResult<bool> {
    let secret_mismatch = first.0.ct_eq(&second.0).not();
    let r_mismatch = first.1.ct_eq(&second.1).not();
    if secret_mismatch.or(r_mismatch).to_bool() {
        return Ok(false);
    }
    Ok(true)
}

fn plausibleCombinations<'a>(
    access_structure: ThresholdAccess,
    shares: &'a [CompactShare],
) -> ADSSResult<Box<dyn Iterator<Item = Vec<&'a CompactShare>> + 'a>> {
    let total_set: Vec<&'a CompactShare> = shares.iter().collect();
    let mut result: Box<dyn Iterator<Item = Vec<&'a CompactShare>> + 'a> =
        Box::new(std::iter::once(total_set));
    for size in ((access_structure.threshold() as usize)..shares.len()).rev() {
        result = Box::new(result.chain(shares.iter().combinations(size)));
    }

    Ok(result)
}


#[cfg(test)]
mod test {
    use crate::{CommonInfo, ShareSlice};

    use super::*;
    use ax::share;
    use hex_literal::hex;
    use shake::{ExtendableOutput, Shake128, Update, digest::array::Array};

    #[test]
    fn smoke_share_split() -> ADSSResult<()> {
        let access_structure = ThresholdAccess::new(2, 3)?;

        let secret = b"Secret message";
        let aad = b"Some aad";
        let coins = b"Yellow SubmarineYellow Submarine".into();

        let input = share(access_structure, secret, coins, aad)?;
        assert_eq!(aad, input.common().aad());

        let result = recover(&input)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(coins, &result.1);
        assert_eq!(input.shares().ids(), result.2);
        

        // Assemble from first two
        let shares = input.shares();
        let common = input.common();
        let recovery = RecoveryInput::new(
            shares[0..2].to_vec(),
            common.clone()
        )?;
        let result = recover(&recovery)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(2, result.2.len());
        assert_eq!(shares[0].id(), result.2[0]);
        assert_eq!(shares[1].id(), result.2[1]);

        // Assemble from last two
        let recovery = RecoveryInput::new(
            shares[1..3].to_vec(),
            common.clone()
        )?;
        let result = recover(&recovery)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(2, result.2.len());
        assert_eq!(shares[1].id(), result.2[0]);
        assert_eq!(shares[2].id(), result.2[1]);

        // Assemble Outer two
        let recovery = RecoveryInput::new(
            vec![shares[0].clone(), shares[2].clone()],
            common.clone()
        )?;
        let result = recover(&recovery)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(2, result.2.len());
        assert_eq!(shares[0].id(), result.2[0]);
        assert_eq!(shares[2].id(), result.2[1]);

        // One corrupt share (2)
        let mut tmp = shares.to_vec();
        tmp[1].secret_part[0] ^= 1;

        let recovery = RecoveryInput::new(
            tmp,
            common.clone()
        )?;
        let result = recover(&recovery)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(2, result.2.len());
        assert!(result.2.contains(&1));
        assert!(result.2.contains(&3));
        assert!(!result.2.contains(&2));
        Ok(())
    }
}
