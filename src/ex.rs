use ctutils::CtEq;
use itertools::Itertools;

use crate::{
    CompactShareCollection, SEC_PARAM_BYTES, ShareCollection, ShareCollectionImpl, ShareInfo,
    ThresholdAccess, ax,
    errors::{ADSSError::IntegrityError, ADSSResult},
};

pub(crate) fn recover<I: ShareInfo, C: ShareCollection<I>>(
    shares: &C,
) -> ADSSResult<(Vec<u8>, [u8; SEC_PARAM_BYTES], Vec<u8>)> {
    let mut result: Option<(Vec<u8>, [u8; SEC_PARAM_BYTES], Vec<u8>)> = None;
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
    first: &(Vec<u8>, [u8; SEC_PARAM_BYTES], Vec<u8>),
    second: &(Vec<u8>, [u8; SEC_PARAM_BYTES], Vec<u8>),
) -> ADSSResult<bool> {
    let secret_mismatch = first.0.ct_eq(&second.0).not();
    let r_mismatch = first.1.ct_eq(&second.1).not();
    if secret_mismatch.or(r_mismatch).to_bool() {
        return Ok(false);
    }
    if second.2.len() >= first.2.len() {
        return Ok(false);
    }
    for x in &second.2 {
        if !first.2.contains(&x) {
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
    use shake::{ExtendableOutput, Shake128, Update, digest::array::Array};

    #[test]
    fn smoke_share_split() -> ADSSResult<()> {
        let access_structure = ThresholdAccess::new(2, 3)?;

        let secret = b"Secret message";
        let aad = b"Some aad";
        let coins = b"Yellow SubmarineYellow Submarine".into();

        let shares = share(access_structure, secret, coins, aad)?;
        assert_eq!(aad, shares.aad()?);
        let shares = shares.expand()?;
        assert_eq!(aad, shares.aad()?);
        for s in &shares {
            assert_eq!(aad, s.aad()?);
        }

        let result = recover(&shares)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(shares.ids()?, result.2);
        

        // Assemble from first two
        let result = recover(&&shares[0..2])?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(2, result.2.len());
        assert_eq!(shares[0].id(), result.2[0]);
        assert_eq!(shares[1].id(), result.2[1]);

        // Assemble from last two
        let result = recover(&&shares[1..3])?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(2, result.2.len());
        assert_eq!(shares[1].id(), result.2[0]);
        assert_eq!(shares[2].id(), result.2[1]);

        // Assemble Outer two
        let tmp = [shares[0].clone(), shares[2].clone()];
        let result = recover(&tmp.as_slice())?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(2, result.2.len());
        assert_eq!(shares[0].id(), result.2[0]);
        assert_eq!(shares[2].id(), result.2[1]);

        // One corrupt share (2)
        let mut tmp = shares.clone();
        tmp[1].secret_part[0] ^= 1;

        let result = recover(&tmp)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(2, result.2.len());
        assert!(result.2.contains(&1));
        assert!(result.2.contains(&3));
        assert!(!result.2.contains(&2));
        Ok(())
    }
}
