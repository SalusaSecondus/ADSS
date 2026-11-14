// We keep all hash/oracle/prf definitions together to make it easier to review for domain separation.

use shake::{ExtendableOutput, Shake256, Update, XofReader};

use crate::SEC_PARAM_BYTES;

const AX_HASH_DOMAIN_SEP: &[u8; 18] = b"C2SP/ADSS/AX/HASH:";
const AX_PRF_DOMAIN_SEP: &[u8; 17] = b"C2SP/ADSS/AX/PRF:";
const AX_CPRF_DOMAIN_SEP: &[u8; 2] = b"C:"; // Must come after AX_PRF_DOMAIN_SEP
const AX_DPRF_DOMAIN_SEP: &[u8; 2] = b"D:"; // Must come after AX_PRF_DOMAIN_SEP
const S1_XOF_DOMAIN_SEP: &[u8; 17] = b"C2SP/ADSS/S1/XOF:";

fn sponge() -> Shake256 {
    Shake256::default()
}

pub(crate) fn multi_hash_part(h: &mut Shake256, data: &[u8]) {
    let len = data.len() as u32;
    h.update(&len.to_be_bytes());
    h.update(data);
}

pub(crate) fn ax_hash() -> Shake256 {
    let mut result = sponge();
    multi_hash_part(&mut result, AX_HASH_DOMAIN_SEP);
    result
}

fn ax_prf(key: &[u8]) -> Shake256 {
    let mut result = sponge();
    multi_hash_part(&mut result, AX_PRF_DOMAIN_SEP);
    multi_hash_part(&mut result, key);
    result
}

pub(crate) fn ax_cprf(key: &[u8], length: usize) -> Vec<u8> {
    let mut prf = ax_prf(key);
    multi_hash_part(&mut prf, AX_CPRF_DOMAIN_SEP);
    let mut result = vec![0u8; length];
    prf.finalize_xof_into(&mut result);
    result
}

pub(crate) fn ax_dprf(key: &[u8]) -> [u8; SEC_PARAM_BYTES] {
    let mut prf = ax_prf(key);
    multi_hash_part(&mut prf, AX_DPRF_DOMAIN_SEP);
    let mut result = [0u8; SEC_PARAM_BYTES];
    prf.finalize_xof_into(&mut result);
    result
}

pub(crate) fn s1_xof(coins: &[u8]) -> impl XofReader {
    let mut result = sponge();
    multi_hash_part(&mut result, S1_XOF_DOMAIN_SEP);
    multi_hash_part(&mut result, coins);
    result.finalize_xof()
}
