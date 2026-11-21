// https://datatracker.ietf.org/doc/html/draft-mcgrew-tss-03

use shake::XofReader;

use crate::{
    CompactShare, RecoveryInput, SEC_PARAM_BYTES, ShareInfo, ShareSlice as _, ThresholdAccess, errors::{ADSSError, ADSSResult}, gf256::GF256, oracles::s1_xof,
};

pub(crate) fn share(
    access_structure: ThresholdAccess,
    message: &[u8],
    r: &[u8],
) -> ADSSResult<Vec<CompactShare>> {
    let r = &mut s1_xof(r);
    let mut shares = vec![
        CompactShare {
            id: 0,
            secret_part: [0u8; SEC_PARAM_BYTES],
            j: [0u8; 2*SEC_PARAM_BYTES],
        };
        access_structure.total() as usize
    ];
    for (idx, share) in shares.iter_mut().enumerate() {
        share.id = (idx + 1) as u8;
    }
    for (idx, s) in message.iter().enumerate() {
        let splits = split_byte(
            s.into(),
            access_structure.threshold(),
            access_structure.total(),
            r,
        );
        for (sidx, val) in splits.iter().enumerate() {
            shares[sidx].secret_part[idx] = *val;
        }
    }
    Ok(shares)
}

pub(crate) fn recover(input: &RecoveryInput) -> ADSSResult<Vec<u8>> {
    // Ensures that we have enough shares
    let shares = input.shares();
    let threshold = input.common().access_structure().threshold();
    if shares.len() < threshold as usize {
        return Err(ADSSError::BelowThreshold(shares.len() as u8, threshold));
    }
    let ids: Vec<GF256> = shares.ids().iter().map(|i| i.into()).collect();
    let mut result = vec![0u8; shares[0].secret_part().len()];
    for (idx, rval) in result.iter_mut().enumerate() {
        let v: Vec<GF256> = shares
            .iter()
            .map(|s| s.secret_part()[idx].into())
            .collect();
        *rval = i(&ids, &v).into();
    }
    Ok(result)
}

fn split_byte<X>(secret: GF256, m: u8, n: u8, xof: &mut X) -> Vec<u8>
where
    X: XofReader,
{
    let mut coefs = vec![0u8; m as usize];
    xof.read(&mut coefs[1..]);
    coefs[0] = secret.into();
    let coefs: Vec<GF256> = coefs.iter().map(|v| v.into()).collect();

    let mut result = vec![0u8; n as usize];
    for (idx, share) in result.iter_mut().enumerate() {
        *share = f(idx + 1, &coefs).into();
    }
    result
}

fn f(x: usize, a: &[GF256]) -> GF256 {
    let x: GF256 = (x as u8).into();
    let mut result = GF256::zero();
    let mut xi = GF256::one();
    for ai in a {
        result += ai * xi;
        xi *= x;
    }
    result
}

fn li(i: usize, u: &[GF256]) -> GF256 {
    let mut result = GF256::one();
    let ui = u[i];
    for (j, uj) in u.iter().enumerate() {
        if j != i {
            let bottom = uj + ui;
            let part = uj / bottom;
            result *= part;
        }
    }
    result
}

fn i(u: &[GF256], v: &[GF256]) -> GF256 {
    // TODO: Check input lengths
    let mut result = GF256::zero();
    for (i, vi) in v.iter().enumerate() {
        result += li(i, u) * vi;
    }
    result
}

#[cfg(test)]
mod test {
    use crate::CommonInfo;

    use super::*;


    #[test]
    fn smoke_share_split() -> ADSSResult<()> {
        let access_structure = ThresholdAccess::new(2, 3)?;

        let secret = b"Secret message that is 32 bytes!";

        let shares = share(access_structure, secret, b"coins")?;

        let common = CommonInfo::new(access_structure, &[], &[])?;
        let recovery = RecoveryInput::new(shares.clone(), common.clone())?;
        let result = recover(&recovery)?;
        assert_eq!(secret.as_slice(), result.as_slice());

        // Assemble from first two
        let recovery = RecoveryInput::new(shares[0..2].to_vec(), common.clone())?;
        let result = recover(&recovery)?;
        assert_eq!(secret.as_slice(), result.as_slice());

        // Assemble from last two
        let recovery = RecoveryInput::new(shares[1..3].to_vec(), common.clone())?;
        let result = recover(&recovery)?;
        assert_eq!(secret.as_slice(), result.as_slice());

        // Assemble Outer two
        let recovery = RecoveryInput::new(
            vec![shares[0].clone(), shares[2].clone()], common.clone())?;

        let result = recover(&recovery)?;
        assert_eq!(secret.as_slice(), result.as_slice());
        Ok(())
    }
}
