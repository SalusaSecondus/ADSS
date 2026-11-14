use ctutils::CtEq;
use shake::{ExtendableOutput, XofReader, digest::{array::Array, consts::U32}};

use crate::{
    CompactShare, CompactShareCollection, SEC_PARAM_ARRAY_LEN, SEC_PARAM_BYTES, ShareCollection, ShareInfo, ThresholdAccess, errors::{
        ADSSError::{IntegrityError, InvalidCoinLength, UnsupportedShareType},
        ADSSResult,
    }, oracles::{ax_cprf, ax_dprf, ax_hash, multi_hash_part}, s1,
};

pub(crate) fn share(
    access_structure: ThresholdAccess,
    message: &[u8],
    r: &Array<u8, SEC_PARAM_ARRAY_LEN>,
    aad: &[u8],
) -> ADSSResult<CompactShareCollection> {
    if r.len() != SEC_PARAM_BYTES {
        return Err(InvalidCoinLength(r.len(), SEC_PARAM_BYTES));
    }
    // ‖ K ‖ L ← H 4κ (A,M,R,T) where |J | = 2κ and |K | = |L | = κ
    let (j, k, l) = jkl(access_structure, message, r, aad)?;
    // C ← M ⊕ f(ε);
    let mut c = ax_cprf(&k, message.len());
    for (dest, src) in c.iter_mut().zip(message.iter()) {
        *dest ^= src;
    }
    let c = c;

    // D ← R ⊕ f(0)
    let mut d = ax_dprf(&k);
    for (dest, src) in d.iter_mut().zip(r) {
        *dest ^= src;
    }
    let d = d;

    let mut public_part = vec![];
    public_part.extend_from_slice(&c);
    public_part.extend_from_slice(&d);
    public_part.extend_from_slice(&j);

    let mut shares = s1::share(access_structure, &k, &l)?;
    shares.public_part = public_part;
    shares.tag = aad.to_vec();
    Ok(shares)
}

pub(crate) fn recover<I: ShareInfo, C: ShareCollection<I>>(
    shares: &C,
) -> ADSSResult<(Vec<u8>, [u8; SEC_PARAM_BYTES], Vec<u8>)> {
    let info = shares.info()?;
    let t = info.len();
    let access_structure = shares.access_structure()?;
    let public_info = shares.public_part()?;
    let (c, d, j) = split_cdj(public_info)?;

    let mut inner_shares = CompactShareCollection {
        shares: vec![
            CompactShare {
                id: 0,
                secret_part: [0u8; SEC_PARAM_BYTES]
            };
            t
        ],
        access_structure,
        public_part: vec![],
        tag: vec![],
    };
    for (dest, src) in inner_shares.shares.iter_mut().zip(info.iter()) {
        dest.id = src.id();
        dest.secret_part.copy_from_slice(src.secret_part());
    }
    let (k, ids) = s1::recover(&inner_shares)?;
    let mut m = ax_cprf(&k, c.len());
    for (dst, src) in m.iter_mut().zip(c.iter()) {
        *dst ^= src;
    }
    let mut r = ax_dprf(&k);
    for (dst, src) in r.iter_mut().zip(d.iter()) {
        *dst ^= src;
    }

    let (j_prime, k_prime, _) = jkl(access_structure, &m, &r, shares.aad()?)?;
    let j_wrong = j_prime.ct_eq(&j).not();
    let k_wrong = k_prime.as_slice().ct_eq(&k).not();
    if j_wrong.or(k_wrong).to_bool() {
        Err(IntegrityError)
    } else {
        Ok((m, r, ids))
    }
}

fn jkl(
    access_structure: ThresholdAccess,
    message: &[u8],
    r: &[u8],
    aad: &[u8],
) -> ADSSResult<(
    [u8; 2 * SEC_PARAM_BYTES],
    [u8; SEC_PARAM_BYTES],
    [u8; SEC_PARAM_BYTES],
)> {
    let mut hash = ax_hash();
    multi_hash_part(&mut hash, &access_structure.serialize());
    multi_hash_part(&mut hash, message);
    multi_hash_part(&mut hash, r);
    multi_hash_part(&mut hash, aad);
    let mut j = [0u8; 2 * SEC_PARAM_BYTES];
    let mut k = [0u8; SEC_PARAM_BYTES];
    let mut l = [0u8; SEC_PARAM_BYTES];
    let mut xof = hash.finalize_xof();
    xof.read(&mut j);
    xof.read(&mut k);
    xof.read(&mut l);
    Ok((j, k, l))
}

fn split_cdj(
    cdj: &[u8],
) -> ADSSResult<(Vec<u8>, [u8; SEC_PARAM_BYTES], [u8; 2 * SEC_PARAM_BYTES])> {
    if cdj.len() < 3 * SEC_PARAM_BYTES {
        return Err(UnsupportedShareType);
    }
    let c_len = cdj.len() - (3 * SEC_PARAM_BYTES);
    let mut c = vec![0u8; c_len];
    c.copy_from_slice(&cdj[..c_len]);
    let mut d = [0u8; SEC_PARAM_BYTES];
    d.copy_from_slice(&cdj[c_len..c_len + SEC_PARAM_BYTES]);
    let mut j = [0u8; 2 * SEC_PARAM_BYTES];
    j.copy_from_slice(&cdj[cdj.len() - 2 * SEC_PARAM_BYTES..]);
    Ok((c, d, j))
}

#[cfg(test)]
mod test {
    use crate::{CommonInfo, Share};

    use super::*;
    use hex_literal::hex;
    use shake::{ExtendableOutput, Shake128, Update};

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
        Ok(())
    }
}
