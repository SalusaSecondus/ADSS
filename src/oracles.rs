use shake::{ExtendableOutput, Shake256, Update, XofReader};

const AX_HASH_DOMAIN_SEP: &[u8; 18] = b"C2SP/ADSS/AX/HASH:";
const AX_PRF_DOMAIN_SEP: &[u8; 17] = b"C2SP/ADSS/AX/PRF:";
const S1_XOF_DOMAIN_SEP: &[u8; 17] = b"C2SP/ADSS/S1/XOF:";

pub(crate) fn sponge() -> Shake256 {
    Shake256::default()
}

pub(crate) fn ax_hash() -> Shake256 {
    sponge().chain(AX_HASH_DOMAIN_SEP)
}

pub(crate) fn ax_prf(key: &[u8]) -> Shake256 {
    let mut result = sponge().chain(AX_PRF_DOMAIN_SEP);
    multi_hash_part(&mut result, key);
    result
}

pub(crate) fn s1_xof(coins: &[u8]) -> impl XofReader {
    sponge()
        .chain(S1_XOF_DOMAIN_SEP)
        .chain(coins)
        .finalize_xof()
}

pub(crate) fn multi_hash_part(h: &mut Shake256, data: &[u8]) {
    let len = data.len() as u64;
    h.update(&len.to_be_bytes());
    h.update(data);
}
