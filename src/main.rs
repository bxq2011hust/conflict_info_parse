use std::convert::TryInto;

use colored::Colorize;
use env_logger::Env;
use log::{error, info};
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value};
use serde_repr::Serialize_repr;
use sha3::Digest;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Cli {
    /// The path of the abi json file
    #[structopt(parse(from_os_str))]
    #[structopt(short, long)]
    abi: std::path::PathBuf,
    /// The path to the file to read
    #[structopt(parse(from_os_str))]
    #[structopt(short, long)]
    path: std::path::PathBuf,
    /// Indicates using GM mode or not.
    #[structopt(short, long)]
    gm: bool,
}

#[derive(Debug, Serialize_repr, PartialOrd, Ord, PartialEq, Eq, Clone)]
#[repr(u8)]
enum ConflictType {
    All = 0,
    #[allow(dead_code)]
    Len,
    Env,
    Var,
    Const,
    None,
}

enum EnvironmentType {
    Caller = 0,
    Origin,
    Now,
    BlockNumber,
    Address,
    Unknown,
}

#[derive(Debug, Serialize, PartialOrd, Ord, PartialEq, Eq, Clone)]
struct ConflictInfo {
    kind: ConflictType,
    #[serde(skip_serializing)]
    selector: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    slot: Option<u32>,
    /// for Var, the value is the index of calldata per 32Bytes, for Env, the value is EnvironmentType
    #[serde(skip_serializing_if = "Vec::is_empty")]
    value: Vec<u32>,
}

fn parse_conflict_info(path: &std::path::Path) -> Vec<ConflictInfo> {
    let mut result = Vec::new();

    let env_csv = path.join("Conflict_EnvConflict.csv");
    let slot_re = Regex::new(r"0x([\da-f]+)").unwrap();
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b'\t')
        .from_path(env_csv.as_path())
        .unwrap();
    for r in rdr.records() {
        let record = r.unwrap();
        // info!("env_csv {:?}, {} ", &record, record.len());
        let selector = u32::from_str_radix(record[1].trim_start_matches("0x"), 16).unwrap();
        let value = match record[2].as_ref() {
            "CALLER" => vec![EnvironmentType::Caller as u32],
            "ORIGIN" => vec![EnvironmentType::Origin as u32],
            "TIMESTAMP" => vec![EnvironmentType::Now as u32],
            "NUMBER" => vec![EnvironmentType::BlockNumber as u32],
            "ADDRESS" => vec![EnvironmentType::Address as u32],
            _ => {
                error!("Unknown environment type: {}", &record[2]);
                vec![EnvironmentType::Unknown as u32]
            }
        };

        let slot = u32::from_str_radix(
            slot_re
                .find(&record[3])
                .unwrap()
                .as_str()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        result.push(ConflictInfo {
            kind: ConflictType::Env,
            selector,
            slot: Some(slot),
            value,
        });
    }
    let mix_csv = path.join("Conflict_MixConflict.csv");
    rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b'\t')
        .from_path(mix_csv.as_path())
        .unwrap();
    for r in rdr.records() {
        let record = r.unwrap();
        let selector = u32::from_str_radix(record[0].trim_start_matches("0x"), 16).unwrap();
        // let slot = u32::from_str_radix(
        //     slot_re
        //         .find(&record[2])
        //         .unwrap()
        //         .as_str()
        //         .trim_start_matches("0x"),
        //     16,
        // )
        // .unwrap();
        result.push(ConflictInfo {
            kind: ConflictType::All,
            selector,
            slot: None,
            value: vec![],
        });
    }
    let call_contract_csv = path.join("Conflict_NoStorageAccessHasContractCalling.csv");
    rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b'\t')
        .from_path(call_contract_csv.as_path())
        .unwrap();
    for r in rdr.records() {
        let record = r.unwrap();
        let selector = u32::from_str_radix(record[0].trim_start_matches("0x"), 16).unwrap();
        result.push(ConflictInfo {
            kind: ConflictType::All,
            selector,
            slot: None,
            value: vec![],
        });
    }

    let var_csv = path.join("Conflict_FunArgConflict.csv");
    rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b'\t')
        .from_path(var_csv.as_path())
        .unwrap();
    for r in rdr.records() {
        let record = r.unwrap();
        let selector = u32::from_str_radix(record[1].trim_start_matches("0x"), 16).unwrap();
        let value = vec![record[2].parse().unwrap()];
        let slot = u32::from_str_radix(
            slot_re
                .find(&record[3])
                .expect(&format!("slot not found {:?}", &record[3]))
                .as_str()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        result.push(ConflictInfo {
            kind: ConflictType::Var,
            selector,
            slot: Some(slot),
            value,
        });
    }

    let dynamic_const_csv = path.join("Conflict_DynaVarConsConflict.csv");
    rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b'\t')
        .from_path(dynamic_const_csv.as_path())
        .unwrap();
    for r in rdr.records() {
        let record = r.unwrap();
        let selector = u32::from_str_radix(record[1].trim_start_matches("0x"), 16).unwrap();
        let slot = u32::from_str_radix(
            slot_re
                .find(&record[2])
                .unwrap()
                .as_str()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        let mut value_hex = record[3].trim_start_matches("0x").to_string();
        if value_hex.len() % 2 != 0 {
            value_hex.insert(0, '0');
        }
        let value = hex::decode(value_hex)
            .unwrap()
            .iter_mut()
            .map(|x| *x as u32)
            .collect();
        result.push(ConflictInfo {
            kind: ConflictType::Const,
            selector,
            slot: Some(slot),
            value,
        });
    }

    let basic_const_csv = path.join("Conflict_BasicVarConsConflict.csv");
    rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b'\t')
        .from_path(basic_const_csv.as_path())
        .unwrap();
    for r in rdr.records() {
        let record = r.unwrap();
        let selector = u32::from_str_radix(record[1].trim_start_matches("0x"), 16).unwrap();
        let mut value_hex = record[2].trim_start_matches("0x").to_string();
        if value_hex.len() % 2 != 0 {
            value_hex.insert(0, '0');
        }
        let value = hex::decode(value_hex)
            .unwrap()
            .iter_mut()
            .map(|x| *x as u32)
            .collect();
        result.push(ConflictInfo {
            kind: ConflictType::Const,
            selector,
            slot: None,
            value,
        });
    }
    let none_csv = path.join("Conflict_NoConflict.csv");
    rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b'\t')
        .from_path(none_csv.as_path())
        .unwrap();
    for r in rdr.records() {
        let record = r.unwrap();
        let selector = u32::from_str_radix(record[0].trim_start_matches("0x"), 16).unwrap();
        result.push(ConflictInfo {
            kind: ConflictType::None,
            selector,
            slot: None,
            value: vec![],
        });
    }
    info!("parse conflicts completed");
    result.sort();
    result.dedup();
    result
}

fn parse_ty(ty_info: &Map<String, Value>) -> String {
    const TUPLE_TY: &str = "tuple";

    let ty = ty_info.get("type").unwrap().as_str().unwrap();
    if ty.starts_with(TUPLE_TY) {
        let components = ty_info.get("components").unwrap().as_array().unwrap();
        let component_types = components
            .iter()
            .map(|component| parse_ty(component.as_object().unwrap()))
            .collect::<Vec<String>>()
            .join(",");
        format!("({}){}", component_types, &ty[TUPLE_TY.len()..])
    } else {
        String::from(ty)
    }
}

fn get_method_signature(method: &Map<String, Value>) -> String {
    let fn_name = String::from(method["name"].as_str().unwrap());
    let inputs = method["inputs"].as_array().unwrap();
    let sig = inputs
        .iter()
        .map(|input| parse_ty(input.as_object().unwrap()))
        .collect::<Vec<String>>()
        .join(",");
    format!("{}({})", fn_name, sig)
}

fn get_method_id(signature: &str, gm: bool) -> u32 {
    if gm {
        let mut sm3_hash = libsm::sm3::hash::Sm3Hash::new(signature.as_bytes());
        let hash = sm3_hash.get_hash();
        u32::from_be_bytes(hash[..4].try_into().unwrap())
    } else {
        let hash = sha3::Keccak256::digest(signature.as_bytes());
        u32::from_be_bytes(hash.as_slice()[..4].try_into().unwrap())
    }
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("error")).init();
    let args = Cli::from_args();
    let abi_content = std::fs::read_to_string(&args.abi)
        .expect(format!("could not read file {}", args.abi.display()).as_str());
    let conflicts = parse_conflict_info(args.path.as_path());

    let mut origin_abi: Value = serde_json::from_str(&abi_content).unwrap();
    origin_abi
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .for_each(|method| {
            let method = method.as_object_mut().unwrap();
            if method.contains_key("name")
                && method.contains_key("type")
                && method["type"] == Value::String("function".into())
            {
                let signature = get_method_signature(method);
                let method_id = get_method_id(&signature, args.gm);
                let method_conflicts: Vec<ConflictInfo> = conflicts
                    .iter()
                    .filter(|conflict| conflict.selector == method_id)
                    .cloned()
                    .collect();
                if method_conflicts.len() != 0 {
                    method.insert(
                        "conflictFields".into(),
                        serde_json::to_value(method_conflicts).unwrap(),
                    );
                }
                if args.gm {
                    method.insert(
                        "selector".into(),
                        serde_json::to_value(vec![get_method_id(&signature, false), method_id])
                            .unwrap(),
                    );
                } else {
                    method.insert(
                        "selector".into(),
                        serde_json::to_value(vec![method_id, get_method_id(&signature, true)])
                            .unwrap(),
                    );
                }
            }
        });
    let new_abi = serde_json::to_string(&origin_abi).unwrap();
    std::fs::write(&args.abi, new_abi).unwrap();
    print!(
        "parse csv and rewrite abi successfully, new abi is saved to {}",
        format!("{}", args.abi.display()).green()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    static ABI_STR: &'static str = r#"[
        {
            "inputs": [],
            "stateMutability": "nonpayable",
            "type": "constructor"
        },
        {
            "inputs": [],
            "name": "StrRead",
            "outputs": [
                {
                    "internalType": "string",
                    "name": "",
                    "type": "string"
                }
            ],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "StrWrite",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "name": "complexMap",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "a",
                    "type": "uint256"
                },
                {
                    "internalType": "uint256",
                    "name": "b",
                    "type": "uint256"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "complexMapReadWithConsKey",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "complexMapWriteWithConsKey",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "name": "dynaArray",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "dynaArrayReadWithConsKey",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "i",
                    "type": "uint256"
                }
            ],
            "name": "dynaArrayReadWithFuncArgKey",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "dynaArrayWriteWithConsKey",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "i",
                    "type": "uint256"
                }
            ],
            "name": "dynaArrayWriteWithFuncArgKey",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "fixedSizeVar",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "fixedSizeVarRead",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "fixedSizeVarWrite",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "x",
                    "type": "uint256"
                }
            ],
            "name": "noStorageAccessAndContractCalling",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "address",
                    "name": "addr",
                    "type": "address"
                }
            ],
            "name": "noStorageAccessHasContractCalling",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "name": "simpleMap",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "address",
                    "name": "",
                    "type": "address"
                }
            ],
            "name": "simpleMapForTestEnv",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "simpleMapIndirectWriteWithEnvKey",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "simpleMapReadWithConsKey",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "x",
                    "type": "uint256"
                }
            ],
            "name": "simpleMapReadWithEnvKey",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "i",
                    "type": "uint256"
                }
            ],
            "name": "simpleMapReadWithFuncArgKey",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "simpleMapWriteWithConsKey",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "simpleMapWriteWithEnvKey",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "i",
                    "type": "uint256"
                }
            ],
            "name": "simpleMapWriteWithFuncArgKey",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "x",
                    "type": "uint256"
                }
            ],
            "name": "simpleMapWriteWithMixKey",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "components": [
                        {
                            "internalType": "uint256",
                            "name": "a",
                            "type": "uint256"
                        },
                        {
                            "internalType": "uint256",
                            "name": "b",
                            "type": "uint256"
                        }
                    ],
                    "internalType": "struct S",
                    "name": "s",
                    "type": "tuple"
                }
            ],
            "name": "simpleMapWriteWithPartStructFuncArgKey",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "x",
                    "type": "uint256"
                },
                {
                    "components": [
                        {
                            "internalType": "uint256",
                            "name": "a",
                            "type": "uint256"
                        },
                        {
                            "internalType": "uint256",
                            "name": "b",
                            "type": "uint256"
                        }
                    ],
                    "internalType": "struct S",
                    "name": "s",
                    "type": "tuple"
                }
            ],
            "name": "simpleMapWriteWithPartStructFuncArgKey2",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "a",
                    "type": "uint256"
                },
                {
                    "components": [
                        {
                            "internalType": "uint256",
                            "name": "a",
                            "type": "uint256"
                        },
                        {
                            "components": [
                                {
                                    "internalType": "string",
                                    "name": "a",
                                    "type": "string"
                                },
                                {
                                    "components": [
                                        {
                                            "internalType": "uint256",
                                            "name": "a",
                                            "type": "uint256"
                                        },
                                        {
                                            "internalType": "uint256",
                                            "name": "b",
                                            "type": "uint256"
                                        }
                                    ],
                                    "internalType": "struct S",
                                    "name": "b",
                                    "type": "tuple"
                                },
                                {
                                    "internalType": "string",
                                    "name": "c",
                                    "type": "string"
                                }
                            ],
                            "internalType": "struct SS",
                            "name": "b",
                            "type": "tuple"
                        },
                        {
                            "internalType": "uint256",
                            "name": "c",
                            "type": "uint256"
                        }
                    ],
                    "internalType": "struct SSS",
                    "name": "sss",
                    "type": "tuple"
                },
                {
                    "internalType": "uint256",
                    "name": "c",
                    "type": "uint256"
                }
            ],
            "name": "simpleMapWriteWithPartStructFuncArgKey3",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "x",
                    "type": "uint256"
                },
                {
                    "components": [
                        {
                            "internalType": "string",
                            "name": "a",
                            "type": "string"
                        },
                        {
                            "components": [
                                {
                                    "internalType": "uint256",
                                    "name": "a",
                                    "type": "uint256"
                                },
                                {
                                    "internalType": "uint256",
                                    "name": "b",
                                    "type": "uint256"
                                }
                            ],
                            "internalType": "struct S",
                            "name": "b",
                            "type": "tuple"
                        },
                        {
                            "internalType": "string",
                            "name": "c",
                            "type": "string"
                        }
                    ],
                    "internalType": "struct SS",
                    "name": "ss",
                    "type": "tuple"
                }
            ],
            "name": "simpleMapWriteWithPartStructFuncArgKey4",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "a",
                    "type": "uint256"
                },
                {
                    "internalType": "uint256[]",
                    "name": "b",
                    "type": "uint256[]"
                },
                {
                    "internalType": "uint256",
                    "name": "c",
                    "type": "uint256"
                }
            ],
            "name": "simpleMapWriteWithPartStructFuncArgKey5",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "a",
                    "type": "uint256"
                },
                {
                    "internalType": "uint256[5]",
                    "name": "b",
                    "type": "uint256[5]"
                },
                {
                    "internalType": "uint256",
                    "name": "c",
                    "type": "uint256"
                }
            ],
            "name": "simpleMapWriteWithPartStructFuncArgKey6",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "simpleStruct",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "a",
                    "type": "uint256"
                },
                {
                    "internalType": "uint256",
                    "name": "b",
                    "type": "uint256"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "simpleStructRead",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "simpleStructWrite",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "str",
            "outputs": [
                {
                    "internalType": "string",
                    "name": "",
                    "type": "string"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        }
    ]"#;

    #[test]
    fn test_simple_selector() {
        let origin_abi: Value = serde_json::from_str(ABI_STR).unwrap();
        let functions = origin_abi
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| {
                let value = v.as_object().unwrap();
                return value.contains_key("name")
                    && value.contains_key("type")
                    && value["type"].as_str().unwrap() == "function";
            })
            .collect::<Vec<&Value>>();

        let str_read = functions
            .iter()
            .find(|v| v["name"].as_str().unwrap() == "StrRead")
            .unwrap()
            .as_object()
            .unwrap();
        let str_read_sig = get_method_signature(str_read);
        assert_eq!(str_read_sig, "StrRead()".to_string());
        let str_read_selector = get_method_id(&str_read_sig, false);
        assert_eq!(
            str_read_selector,
            u32::from_str_radix("4db0cdb2", 16).unwrap()
        );

        let str_write = functions
            .iter()
            .find(|v| v["name"].as_str().unwrap() == "StrWrite")
            .unwrap()
            .as_object()
            .unwrap();
        let str_write_sig = get_method_signature(str_write);
        assert_eq!(str_write_sig, "StrWrite()".to_string());
        let str_write_selector = get_method_id(&str_write_sig, false);
        assert_eq!(
            str_write_selector,
            u32::from_str_radix("7ea33fd1", 16).unwrap()
        );

        let complex_map = functions
            .iter()
            .find(|v| v["name"].as_str().unwrap() == "complexMap")
            .unwrap()
            .as_object()
            .unwrap();
        let complex_map_sig = get_method_signature(complex_map);
        assert_eq!(complex_map_sig, "complexMap(uint256)".to_string());
        let complex_map_selector = get_method_id(&complex_map_sig, false);
        assert_eq!(
            complex_map_selector,
            u32::from_str_radix("3e49c8f4", 16).unwrap()
        );
        let simple_map_write_with_part_struct_func_arg_key = functions
            .iter()
            .find(|v| v["name"].as_str().unwrap() == "simpleMapWriteWithPartStructFuncArgKey")
            .unwrap()
            .as_object()
            .unwrap();
        let simple_map_write_with_part_struct_func_arg_key_sig =
            get_method_signature(simple_map_write_with_part_struct_func_arg_key);
        assert_eq!(
            simple_map_write_with_part_struct_func_arg_key_sig,
            "simpleMapWriteWithPartStructFuncArgKey((uint256,uint256))".to_string()
        );
        let simple_map_write_with_part_struct_func_arg_key_selector =
            get_method_id(&simple_map_write_with_part_struct_func_arg_key_sig, false);
        assert_eq!(
            simple_map_write_with_part_struct_func_arg_key_selector,
            u32::from_str_radix("c158e6ef", 16).unwrap()
        );
        let simple_map_write_with_part_struct_func_arg_key = functions
            .iter()
            .find(|v| v["name"].as_str().unwrap() == "simpleMapWriteWithPartStructFuncArgKey2")
            .unwrap()
            .as_object()
            .unwrap();
        let simple_map_write_with_part_struct_func_arg_key_sig =
            get_method_signature(simple_map_write_with_part_struct_func_arg_key);
        assert_eq!(
            simple_map_write_with_part_struct_func_arg_key_sig,
            "simpleMapWriteWithPartStructFuncArgKey2(uint256,(uint256,uint256))".to_string()
        );
        let simple_map_write_with_part_struct_func_arg_key_selector =
            get_method_id(&simple_map_write_with_part_struct_func_arg_key_sig, false);
        assert_eq!(
            simple_map_write_with_part_struct_func_arg_key_selector,
            u32::from_str_radix("e407048d", 16).unwrap()
        );
        let simple_map_write_with_part_struct_func_arg_key = functions
            .iter()
            .find(|v| v["name"].as_str().unwrap() == "simpleMapWriteWithPartStructFuncArgKey3")
            .unwrap()
            .as_object()
            .unwrap();
        let simple_map_write_with_part_struct_func_arg_key_sig =
            get_method_signature(simple_map_write_with_part_struct_func_arg_key);
        assert_eq!(
            simple_map_write_with_part_struct_func_arg_key_sig,
            "simpleMapWriteWithPartStructFuncArgKey3(uint256,(uint256,(string,(uint256,uint256),string),uint256),uint256)"
                .to_string()
        );
        let simple_map_write_with_part_struct_func_arg_key_selector =
            get_method_id(&simple_map_write_with_part_struct_func_arg_key_sig, false);
        assert_eq!(
            simple_map_write_with_part_struct_func_arg_key_selector,
            u32::from_str_radix("3894de57", 16).unwrap()
        );

        let simple_map_write_with_part_struct_func_arg_key = functions
            .iter()
            .find(|v| v["name"].as_str().unwrap() == "simpleMapWriteWithPartStructFuncArgKey4")
            .unwrap()
            .as_object()
            .unwrap();
        let simple_map_write_with_part_struct_func_arg_key_sig =
            get_method_signature(simple_map_write_with_part_struct_func_arg_key);
        assert_eq!(
            simple_map_write_with_part_struct_func_arg_key_sig,
            "simpleMapWriteWithPartStructFuncArgKey4(uint256,(string,(uint256,uint256),string))"
                .to_string()
        );
        let simple_map_write_with_part_struct_func_arg_key_selector =
            get_method_id(&simple_map_write_with_part_struct_func_arg_key_sig, false);
        assert_eq!(
            simple_map_write_with_part_struct_func_arg_key_selector,
            u32::from_str_radix("9f440047", 16).unwrap()
        );

        let simple_map_write_with_part_struct_func_arg_key = functions
            .iter()
            .find(|v| v["name"].as_str().unwrap() == "simpleMapWriteWithPartStructFuncArgKey5")
            .unwrap()
            .as_object()
            .unwrap();
        let simple_map_write_with_part_struct_func_arg_key_sig =
            get_method_signature(simple_map_write_with_part_struct_func_arg_key);
        assert_eq!(
            simple_map_write_with_part_struct_func_arg_key_sig,
            "simpleMapWriteWithPartStructFuncArgKey5(uint256,uint256[],uint256)".to_string()
        );
        let simple_map_write_with_part_struct_func_arg_key_selector =
            get_method_id(&simple_map_write_with_part_struct_func_arg_key_sig, false);
        assert_eq!(
            simple_map_write_with_part_struct_func_arg_key_selector,
            u32::from_str_radix("5a0495fd", 16).unwrap()
        );

        let simple_map_write_with_part_struct_func_arg_key = functions
            .iter()
            .find(|v| v["name"].as_str().unwrap() == "simpleMapWriteWithPartStructFuncArgKey6")
            .unwrap()
            .as_object()
            .unwrap();
        let simple_map_write_with_part_struct_func_arg_key_sig =
            get_method_signature(simple_map_write_with_part_struct_func_arg_key);
        assert_eq!(
            simple_map_write_with_part_struct_func_arg_key_sig,
            "simpleMapWriteWithPartStructFuncArgKey6(uint256,uint256[5],uint256)".to_string()
        );
        let simple_map_write_with_part_struct_func_arg_key_selector =
            get_method_id(&simple_map_write_with_part_struct_func_arg_key_sig, false);
        assert_eq!(
            simple_map_write_with_part_struct_func_arg_key_selector,
            u32::from_str_radix("d07c919a", 16).unwrap()
        );
    }
}
