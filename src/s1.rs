// https://datatracker.ietf.org/doc/html/draft-mcgrew-tss-03

use shake::XofReader;

use crate::{
    CompactShare, CompactShareCollection, SEC_PARAM_BYTES, ShareCollection, ShareInfo, ThresholdAccess, errors::{ADSSError::UnsupportedShareType, ADSSResult}, gf256::GF256, oracles::s1_xof,
};

pub(crate) fn share(
    access_structure: ThresholdAccess,
    message: &[u8],
    r: &[u8],
) -> ADSSResult<CompactShareCollection> {
    let r = &mut s1_xof(r);
    let mut shares = vec![
        CompactShare {
            id: 0,
            secret_part: [0u8; SEC_PARAM_BYTES],
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
    Ok(CompactShareCollection {
        shares,
        access_structure,
        public_part: vec![],
        tag: vec![],
    })
}

pub(crate) fn recover<I: ShareInfo, S: ShareCollection<I>>(shares: &S) -> ADSSResult<(Vec<u8>, Vec<u8>)> {
    // Ensures that we have enough shares
    shares.access_structure()?;
    // Checks for duplicate Ids
    let ids: Vec<GF256> = shares.ids()?.iter().map(|i| i.into()).collect();
    // // We don't support aad or public data
    // if !shares.aad()?.is_empty() || !shares.public_part()?.is_empty() {
    //     return Err(UnsupportedShareType);
    // }
    let mut result = vec![0u8; shares.info()?[0].secret_part().len()];
    for (idx, rval) in result.iter_mut().enumerate() {
        let v: Vec<GF256> = shares
            .info()?
            .iter()
            .map(|s| s.secret_part()[idx].into())
            .collect();
        *rval = i(&ids, &v).into();
    }
    Ok((result, shares.ids()?.to_vec()))
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
    use super::*;


    #[test]
    fn smoke_share_split() -> ADSSResult<()> {
        let access_structure = ThresholdAccess::new(2, 3)?;

        let secret = b"Secret message that is 32 bytes!";

        let shares = share(access_structure, secret, b"coins")?;
        let shares = shares.expand()?;

        let result = recover(&shares)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(shares.ids()?, result.1);

        // Assemble from first two
        let result = recover(&&shares[0..2])?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(2, result.1.len());
        assert_eq!(shares[0].id(), result.1[0]);
        assert_eq!(shares[1].id(), result.1[1]);

        // Assemble from last two
        let result = recover(&&shares[1..3])?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(2, result.1.len());
        assert_eq!(shares[1].id(), result.1[0]);
        assert_eq!(shares[2].id(), result.1[1]);

        // Assemble Outer two
        let tmp = [shares[0].clone(), shares[2].clone()];
        let result = recover(&tmp.as_slice())?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(2, result.1.len());
        assert_eq!(shares[0].id(), result.1[0]);
        assert_eq!(shares[2].id(), result.1[1]);
        Ok(())
    }
}
