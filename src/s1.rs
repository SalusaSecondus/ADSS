// https://datatracker.ietf.org/doc/html/draft-mcgrew-tss-03

use shake::XofReader;

use crate::{
    CompactShare, CompactShareCollection, ShareCollection, ShareInfo, ThresholdAccess, errors::{ADSSError::UnsupportedShareType, ADSSResult}, gf256::GF256, oracles::s1_xof,
};

pub(crate) fn share(
    access_structure: ThresholdAccess,
    message: &[u8],
    r: &[u8],
) -> ADSSResult<CompactShareCollection>
{
    let r = &mut s1_xof(r);
    let mut shares = vec![
        CompactShare {
            id: 0,
            secret_part: vec![0u8; message.len()],
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
    Ok(CompactShareCollection { shares, access_structure, public_part: vec![], tag: vec![] })
}

pub(crate) fn recover<S: ShareCollection>(shares: &S) -> ADSSResult<(Vec<u8>, S)> {
    // Ensures that we have enough shares
    shares.access_structure()?;
    // Checks for duplicate Ids
    let ids: Vec<GF256> = shares.ids()?.iter().map(|i| i.into()).collect();
    // We don't support aad or public data
    if !shares.aad()?.is_empty() || !shares.public_part()?.is_empty() {
        return Err(UnsupportedShareType);
    }
    let mut result = vec![0u8; shares.info()?[0].secret_part().len()];
    for (idx, rval) in result.iter_mut().enumerate() {
        let v: Vec<GF256> = shares.info()?.iter().map(|s| s.secret_part()[idx].into()).collect();
        *rval = i(&ids, &v).into();
    }
    Ok((result, shares.clone()))
}

// TODO: Remove
fn split<X>(secret: &[u8], m: u8, n: u8, xof: &mut X) -> ADSSResult<Vec<Vec<u8>>>
where
    X: XofReader,
{
    // TODO: Add argument checks
    let mut result = vec![vec![0u8; secret.len() + 1]; n as usize];
    for (idx, val) in result.iter_mut().enumerate() {
        val[0] = (idx + 1) as u8;
    }
    for (idx, s) in secret.iter().enumerate() {
        let splits = split_byte(s.into(), m, n, xof);
        for (sidx, val) in splits.iter().enumerate() {
            result[sidx][idx + 1] = *val;
        }
    }
    Ok(result)
}

// TODO: Remove
pub fn reconstruct(shares: &[Vec<u8>]) -> ADSSResult<Vec<u8>> {
    // TODO: Check inputs
    let mut result = vec![0; shares[0].len() - 1];
    let u: Vec<GF256> = shares.iter().map(|s| s[0].into()).collect();

    for (idx, rval) in result.iter_mut().enumerate() {
        let v: Vec<GF256> = shares.iter().map(|s| s[idx + 1].into()).collect();
        *rval = i(&u, &v).into();
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
    use crate::Share;

use super::*;
    use hex_literal::hex;
    use shake::{ExtendableOutput, Shake128, Update};

    #[test]
    fn smoke_kat() -> ADSSResult<()> {
        let share1: Vec<u8> = hex!("01B9FA07E185").into();
        let share2: Vec<u8> = hex!("02F5409B4511").into();
        let shares = vec![share1, share2];

        let result = reconstruct(&shares)?;
        assert_eq!(&result, &hex!("7465737400"));
        Ok(())
    }

    #[test]
    fn smoke_split() -> ADSSResult<()> {
        let secret = b"Secret message";
        let mut shake = Shake128::default();
        shake.update(b"Some seed");

        let shares = split(secret, 2, 3, &mut shake.finalize_xof())?;

        let recombined = reconstruct(&shares)?;
        assert_eq!(secret.as_slice(), recombined.as_slice());

        // Assemble from first two
        let recombined = reconstruct(&shares[0..2])?;
        assert_eq!(secret.as_slice(), recombined.as_slice());

        // Assemble from last two
        let recombined = reconstruct(&shares[1..3])?;
        assert_eq!(secret.as_slice(), recombined.as_slice());

        // Assemble Outer two
        let tmp = [shares[0].clone(), shares[2].clone()];
        let recombined = reconstruct(&tmp)?;
        assert_eq!(secret.as_slice(), recombined.as_slice());
        Ok(())
    }

    #[test]
    fn smoke_share_kat() -> ADSSResult<()> {
        let access_structure = ThresholdAccess::new(2, 2)?;
        let share1 = Share {
            id: 1,
            access_structure,
            secret_part: hex!("B9FA07E185").to_vec(),
            public_part: vec![],
            tag: vec![],
        };
        let share2 = Share {
            id: 2,
            access_structure,
            secret_part: hex!("F5409B4511").to_vec(),
            public_part: vec![],
            tag: vec![],
        };
        let shares = vec![share1, share2];

        let result = recover(&shares)?;
        assert_eq!(&result.0, &hex!("7465737400"));
        assert_eq!(shares.len(), result.1.len());
        for v in shares.iter().zip(result.1.iter()) {
            assert_eq!(v.0, v.1);
        }
        Ok(())
    }

    #[test]
    fn smoke_share_split() -> ADSSResult<()> {
        let access_structure = ThresholdAccess::new(2, 3)?;

        let secret = b"Secret message";

        let shares = share(access_structure, secret, b"coins")?;
        let shares = shares.expand()?;

        let result = recover(&shares)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(shares.info()?.len(), result.1.info()?.len());
        for v in shares.info()?.iter().zip(result.1.info()?.iter()) {
            assert_eq!(v.0, v.1);
        }

        // Assemble from first two
        let result = recover(&&shares[0..2])?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(2, result.1.len());
        let result = result.1.expand()?;
        assert_eq!(shares[0], result[0]);
        assert_eq!(shares[1], result[1]);

        // Assemble from last two
        let result = recover(&&shares[1..3])?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(2, result.1.len());
        let result = result.1.expand()?;
        assert_eq!(shares[1], result[0]);
        assert_eq!(shares[2], result[1]);

        // Assemble Outer two
        let tmp = [shares[0].clone(), shares[2].clone()];
        let result = recover(&tmp.as_slice())?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(2, result.1.len());
        let result = result.1.expand()?;
        assert_eq!(shares[0], result[0]);
        assert_eq!(shares[2], result[1]);
        Ok(())
    }
}
