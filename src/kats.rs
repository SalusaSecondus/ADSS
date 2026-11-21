use std::collections::HashMap;

use anyhow::{Result, bail};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use shake::digest::common::Iv;

use crate::{COMPACT_SHARE_LENGTH, CommonInfo, CompactShare, ExpandedShare, RecoveryInput, SEC_PARAM_BYTES, ShareSlice, ThresholdAccess, errors::ADSSResult, recover_from_subset, recover_secret, share_secret};

const VECTOR_JSON: &str = include_str!("../test_vectors.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestResult {
    ShareError,
    RecoveryError,
    CommonError,
    RecoveryInputError,
    RecoverySuccess,
    RecoverySubsetSuccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestVector {
    index: u32,
    shares: Vec<String>,
    common: Option<String>,
    result: TestResult,
    iv: String,
    aad: String,
    secret: String,
    id_subset: Vec<u8>,
}

fn execute_vector(v: &TestVector) -> anyhow::Result<()> {
    let input = if let Some(common_hex) = &v.common {
        let common: ADSSResult<CommonInfo> = hex::decode(common_hex)?.as_slice().try_into();
        if v.result == TestResult::CommonError {
            assert!(common.is_err(), "{}", &v.index);
        }
        let common = common?;
        let mut shares = vec![];
        for s in &v.shares {
            let s = hex::decode(s)?;
            let tmp: ADSSResult<CompactShare> = s.as_slice().try_into();
            if tmp.is_err() {
                if v.result == TestResult::ShareError {
                    return Ok(());
                } else {
                    bail!("Error parsing share: {}, {:?}", v.index, tmp.err());
                }
            }
            shares.push(tmp?);
        }
        if v.result == TestResult::ShareError {
            bail!("missing expected error on shares: {}", v.index);
        }
        RecoveryInput::new(shares, common)
    } else {
        let mut shares = vec![];
        for s in &v.shares {
            let s = hex::decode(s)?;
            let tmp: ADSSResult<ExpandedShare> = s.as_slice().try_into();
            if tmp.is_err() {
                if v.result == TestResult::ShareError {
                    return Ok(());
                } else {
                    bail!("Error parsing share: {}, {:?}", v.index, tmp.err());
                }
            }
            shares.push(tmp?);
        }
        if v.result == TestResult::ShareError {
            bail!("missing expected error on shares: {}", v.index);
        }
        shares.as_slice().try_into()
    };
    if input.is_err() {
        if v.result == TestResult::RecoveryInputError {
            return Ok(());
        } else {
            bail!(
                "error creating RecoveryInput: {}, {:?}",
                v.index,
                input.err()
            );
        }
    } else if v.result == TestResult::RecoveryInputError {
        bail!("missing expected error on RecoveryInput: {}", v.index);
    }
    let input = input?;
    let aad = hex::decode(&v.aad)?;
    assert_eq!(&aad, input.common().aad(), "{}", v.index);
    
    if v.result == TestResult::RecoveryError {
        assert!(recover_secret(&input).is_err(),  "missing recovery error: {}", v.index);
        return Ok(())
    } else if v.result == TestResult::RecoverySuccess {
        let expected = hex::decode(&v.secret)?;
        let iv = hex::decode(&v.iv)?;
        let result = recover_secret(&input)?;
        assert_eq!(expected, result.0, "{}", v.index);
        assert_eq!(&iv, &result.1, "{}", v.index);
    } else if v.result == TestResult::RecoverySubsetSuccess {
        let expected = hex::decode(&v.secret)?;
        let iv = hex::decode(&v.iv)?;
        let mut result = recover_from_subset(&input)?;
        assert_eq!(expected, result.0, "{}", v.index);
        assert_eq!(&iv, &result.1, "{}", v.index);
        result.2.sort();
        assert_eq!(v.id_subset, result.2, "{}", v.index);
    } else {
        panic!("Unexpected test result: {:?}", v.result);
    };
    // Attempt reconstruction
    let secret = hex::decode(&v.secret)?;
    let iv : [u8; SEC_PARAM_BYTES] = hex::decode(&v.iv)?.try_into().unwrap();
    let ids = &v.id_subset;
    let result = share_secret(input.common.access_structure, &secret, &iv.into(), &aad)?;
    assert_eq!(input.common(), result.common(), "{}", v.index);
    let mut expected_map = HashMap::new();
    for share in input.shares() {
        expected_map.insert(share.id, share.clone());
    }
    let expected_map = expected_map;
    let mut actual_map  = HashMap::new();
    for share in result.shares() {
        actual_map.insert(share.id, share.clone());
    }
    let actual_map = actual_map;
    for id in ids {
        assert_eq!(expected_map.get(id), actual_map.get(id),  "{}", v.index);
    }
    Ok(())
}

// #[test]
// fn smoke() {
//     let v = TestVector {
//         shares: vec!["Foo".to_string(), "bar".to_string()],
//         common: None,
//         result: TestResult::RecoverySuccess(vec![0, 1, 2, 3, 4])
//     };
//     let tmp = serde_json::to_string(&v).unwrap();
//     assert_eq!("", tmp);
// }

#[test]
fn test_vectors() -> Result<()> {
    let vectors : Vec<TestVector> = serde_json::from_str(VECTOR_JSON)?;
    for v in &vectors {
        execute_vector(v)?;
    }
    println!("Tested {} cases", vectors.len());
    Ok(())
}

#[test]
#[ignore = "vector generation only"]
fn generate_vectors() -> Result<()> {
    let zero_coins = [0u8; SEC_PARAM_BYTES];
    let aad = vec![0, 1, 2, 3];
    let secret = b"HelloWorld";
    let access_structure = ThresholdAccess::new(2, 3)?;
    let input = share_secret(access_structure, secret, &zero_coins.into(), &aad)?;
    
    let mut vectors = vec![
        build_vector(0, secret, &zero_coins, &input)?,
        build_expanded_vector(1, secret, &zero_coins, &input)?
    ];
    let mut idx = vectors.len() as u32;
    for i in 0..input.shares().len() {
        let mut tmp = input.clone();
        tmp.shares.remove(i);
        vectors.push(build_vector(idx, secret, &zero_coins, &tmp)?);
        idx += 1;
        vectors.push(build_expanded_vector(idx, secret, &zero_coins, &tmp)?);
        idx += 1;
    }
    {
        let mut tmp = input.clone();
        tmp.shares.swap(0, 1);
        tmp.shares.remove(2);
        vectors.push(build_vector(idx, secret, &zero_coins, &tmp)?);
        idx += 1;
        vectors.push(build_expanded_vector(idx, secret, &zero_coins, &tmp)?);
        idx += 1;
    }
    
    // let mut tmp = build_vector(1, secret, &zero_coins, &input)?;
    println!("[");
    for v in &vectors {
        println!("  {},", serde_json::to_string(&v)?);
    }
    println!("]");
    Ok(())
}

fn build_vector(index: u32, secret: &[u8], iv: &[u8], input: &RecoveryInput) -> Result<TestVector> {
    let mut shares = vec![];
    for share in input.shares() {
        let tmp : [u8; COMPACT_SHARE_LENGTH] = share.into();
        shares.push(hex::encode(tmp));
    }
    let common = hex::encode(std::convert::Into::<Vec<u8>>::into(input.common()));
    let aad = hex::encode(input.common().aad());
    let secret = hex::encode(secret);
    let mut id_subset = input.shares().ids();
    id_subset.sort();
    Ok(
        TestVector { index, shares, common: Some(common), result: TestResult::RecoverySuccess, iv: hex::encode(iv), aad, secret, id_subset }
    )
}

fn build_expanded_vector(index: u32, secret: &[u8], iv: &[u8], input: &RecoveryInput) -> Result<TestVector> {
    let es : Vec<ExpandedShare> = input.into();
    let mut shares = vec![];
    for share in &es {
        let tmp : Vec<u8> = share.into();
        shares.push(hex::encode(tmp));
    }
    let aad = hex::encode(input.common().aad());
    let secret = hex::encode(secret);
    let mut id_subset = input.shares().ids();
    id_subset.sort();
    Ok(
        TestVector { index, shares, common: None, result: TestResult::RecoverySuccess, iv: hex::encode(iv), aad, secret, id_subset }
    )
}