use ctutils::CtEq;
use shake::{ExtendableOutput, XofReader, digest::array::Array};

use crate::{
    RecoveryInput, SEC_PARAM_ARRAY_LEN, SEC_PARAM_BYTES, ThresholdAccess, errors::{
        ADSSError::{IntegrityError, InvalidCoinLength, UnsupportedShareType},
        ADSSResult,
    }, oracles::{ax_cprf, ax_dprf, ax_hash, ax_kprf, multi_hash_part}, s1,
};

pub(crate) fn share(
    access_structure: ThresholdAccess,
    message: &[u8],
    r: &Array<u8, SEC_PARAM_ARRAY_LEN>,
    aad: &[u8],
) -> ADSSResult<RecoveryInput> {
    if r.len() != SEC_PARAM_BYTES {
        return Err(InvalidCoinLength(r.len(), SEC_PARAM_BYTES));
    }
    // ‖ K ‖ L ← H 4κ (A,M,R,T) where |J | = 2κ and |K | = |L | = κ
    let (j, k, l) = jkl(access_structure, message, r, aad)?;
    let k_prime = ax_kprf(&k, aad);

    // C ← M ⊕ f(ε);
    let mut c = ax_cprf(&k_prime, message.len());
    for (dest, src) in c.iter_mut().zip(message.iter()) {
        *dest ^= src;
    }
    let c = c;
    // D ← R ⊕ f(0)
    let mut d = ax_dprf(&k_prime);
    for (dest, src) in d.iter_mut().zip(r) {
        *dest ^= src;
    }
    let d = d;
    
    let mut public_part = vec![];
    public_part.extend_from_slice(&c);
    public_part.extend_from_slice(&d);
    public_part.extend_from_slice(&j);
    
    let mut shares = s1::share(access_structure, &k, &l)?;

    Ok(
        RecoveryInput { shares, common: crate::CommonInfo { access_structure, public_part, aad: aad.to_vec() } }
    )
}

pub(crate) fn recover(input: &RecoveryInput) -> ADSSResult<(Vec<u8>, [u8; SEC_PARAM_BYTES])> {
    let access_structure = input.common().access_structure();
    let public_info = input.common().public_part();
    let (c, d, j) = split_cdj(public_info)?;


    let k = s1::recover(&input)?;
    let k_prime = ax_kprf(&k, input.common().aad());
    let mut m = ax_cprf(&k_prime, c.len());
    for (dst, src) in m.iter_mut().zip(c.iter()) {
        *dst ^= src;
    }
    let mut r = ax_dprf(&k_prime);
    for (dst, src) in r.iter_mut().zip(d.iter()) {
        *dst ^= src;
    }

    let (j_prime, k_prime, _) = jkl(access_structure, &m, &r, input.common().aad())?;
    let j_wrong = j_prime.ct_eq(&j).not();
    let k_wrong = k_prime.as_slice().ct_eq(&k).not();
    if j_wrong.or(k_wrong).to_bool() {
        Err(IntegrityError)
    } else {
        Ok((m, r))
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

    use super::*;

    #[test]
    fn smoke_share_split() -> ADSSResult<()> {
        let access_structure = ThresholdAccess::new(2, 3)?;

        let secret = b"Secret message";
        let aad = b"Some aad";
        let coins = b"Yellow SubmarineYellow Submarine".into();

        let input = share(access_structure, secret, coins, aad)?;
        let shares = input.shares();
        let common = input.common();
        assert_eq!(aad, input.common().aad());

        let result = recover(&input)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(&result.1, coins);

        // Assemble from first two
        let recovery = RecoveryInput::new(
            input.shares()[0..2].to_vec(), common.clone())?;
        let result = recover(&recovery)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(&result.1, coins);

        // Assemble from last two
        let recovery = RecoveryInput::new(
            input.shares()[1..3].to_vec(), common.clone())?;
        let result = recover(&recovery)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(&result.1, coins);

        // Assemble Outer two
        let recovery = RecoveryInput::new(
            vec![shares[0].clone(), shares[2].clone()], common.clone())?;

        let result = recover(&recovery)?;
        assert_eq!(secret.as_slice(), result.0.as_slice());
        assert_eq!(&result.1, coins);
        Ok(())
    }
}
