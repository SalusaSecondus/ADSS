use::anyhow::Result;
use shake::XofReader;

use crate::gf256::GF256;

// TODO: Add custom errors
// TODO: SHAKE256 or 512?
pub fn split<X>(secret: &[u8], m: u8, n: u8, xof: &mut X) -> Result<Vec<Vec<u8>>>
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

pub fn reconstruct(shares: &[Vec<u8>]) -> Result<Vec<u8>> {
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
    use super::*;
    use hex_literal::hex;
    use shake::{ExtendableOutput, Shake128, Update};

    #[test]
    fn smoke_kate() -> Result<()> {
        let share1: Vec<u8> = hex!("01B9FA07E185").into();
        let share2: Vec<u8> = hex!("02F5409B4511").into();
        let shares = vec![share1, share2];

        let result = reconstruct(&shares)?;
        assert_eq!(&result, &hex!("7465737400"));
        Ok(())
    }

    #[test]
    fn smoke_split() -> Result<()> {
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
}
