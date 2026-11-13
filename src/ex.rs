use ctutils::CtEq;
use itertools::Itertools;

use crate::{
    CompactShareCollection, SEC_PARAM_BYTES, ShareCollection, ShareCollectionImpl, ShareInfo,
    ThresholdAccess, ax,
    errors::{ADSSError::IntegrityError, ADSSResult},
};

pub(crate) fn recover<I: ShareInfo, C: ShareCollection<I>>(
    shares: &C,
) -> ADSSResult<(Vec<u8>, [u8; SEC_PARAM_BYTES], CompactShareCollection)> {
    let mut result: Option<(Vec<u8>, [u8; SEC_PARAM_BYTES], CompactShareCollection)> = None;
    let mut inner = ShareCollectionImpl::<I> {
        shares: vec![],
        access_structure: shares.access_structure()?,
        public_part: shares.public_part()?.to_vec(),
        tag: shares.aad()?.to_vec(),
    };
    for attempt in plausibleCombinations(shares.access_structure()?, shares.info()?)? {
        let cloned: Vec<I> = attempt.iter().cloned().cloned().collect();
        inner.shares = cloned;

        let partial_result = ax::recover(&inner);
        if let Ok(candidate) = partial_result {
            if let Some(prior) = &result {
                if !compatibleResults(prior, &candidate)? {
                    return Err(IntegrityError);
                }
            } else {
                result = Some(candidate.to_owned());
            }
        }
    }

    result.ok_or(IntegrityError)
}

fn compatibleResults(
    first: &(Vec<u8>, [u8; SEC_PARAM_BYTES], CompactShareCollection),
    second: &(Vec<u8>, [u8; SEC_PARAM_BYTES], CompactShareCollection),
) -> ADSSResult<bool> {
    let secret_mismatch = first.0.ct_eq(&second.0).not();
    let r_mismatch = first.1.ct_eq(&second.1).not();
    if secret_mismatch.or(r_mismatch).to_bool() {
        return Ok(false);
    }
    if second.2.shares_len()? >= first.2.shares_len()? {
        return Ok(false);
    }
    let first_ids = first.2.ids()?;
    for x in second.2.ids()? {
        if !first_ids.contains(&x) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn plausibleCombinations<'a, S: ShareInfo>(
    access_structure: ThresholdAccess,
    shares: &'a [S],
) -> ADSSResult<Box<dyn Iterator<Item = Vec<&'a S>> + 'a>> {
    let total_set: Vec<&'a S> = shares.iter().collect();
    let mut result: Box<dyn Iterator<Item = Vec<&'a S>> + 'a> =
        Box::new(std::iter::once(total_set));
    for size in ((access_structure.threshold() as usize)..shares.len()).rev() {
        result = Box::new(result.chain(shares.iter().combinations(size)));
    }

    Ok(result)
}

#[cfg(test)]
mod test {
    use crate::{CommonInfo, Share};

    use super::*;
    use ax::share;
    use hex_literal::hex;
    use shake::{ExtendableOutput, Shake128, Update};

    #[test]
    fn smoke_share_split() -> ADSSResult<()> {
        let access_structure = ThresholdAccess::new(2, 3)?;

        let secret = b"Secret message";
        let aad = b"Some aad";
        let coins = b"Yellow SubmarineYellow Submarine";

        let shares = share(access_structure, secret, coins, aad)?;
        assert_eq!(aad, shares.aad()?);
        let shares = shares.expand()?;
        assert_eq!(aad, shares.aad()?);
        for s in &shares {
            assert_eq!(aad, s.aad()?);
        }

        let result = recover(&shares)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(shares.info()?.len(), result.2.info()?.len());
        let result = result.2.expand()?;
        for v in shares.iter().zip(result.iter()) {
            assert_eq!(v.0, v.1);
        }

        // Assemble from first two
        let result = recover(&&shares[0..2])?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        let result = result.2.expand()?;
        assert_eq!(2, result.len());
        assert_eq!(shares[0], result[0]);
        assert_eq!(shares[1], result[1]);

        // Assemble from last two
        let result = recover(&&shares[1..3])?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        let result = result.2.expand()?;
        assert_eq!(2, result.len());
        assert_eq!(shares[1], result[0]);
        assert_eq!(shares[2], result[1]);

        // Assemble Outer two
        let tmp = [shares[0].clone(), shares[2].clone()];
        let result = recover(&tmp.as_slice())?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        let result = result.2.expand()?;
        assert_eq!(2, result.len());
        assert_eq!(shares[0], result[0]);
        assert_eq!(shares[2], result[1]);

        // One corrupt share (2)
        let mut tmp = shares.clone();
        tmp[1].secret_part[0] ^= 1;

        let result = recover(&tmp)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        let result = result.2.expand()?;
        assert_eq!(2, result.len());
        assert!(result.ids()?.contains(&1));
        assert!(result.ids()?.contains(&3));
        assert!(!result.ids()?.contains(&2));
        Ok(())
    }
}
