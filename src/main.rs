use std::convert::TryInto;

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

#[derive(Debug, Serialize_repr, Clone)]
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

#[derive(Debug, Serialize, Clone)]
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
    let slot_re = Regex::new(r"0x(\d+)").unwrap();
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
        let slot = u32::from_str_radix(slot_re.find(&record[3]).unwrap().as_str(), 16).unwrap();
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
        let selector = u32::from_str_radix(record[1].trim_start_matches("0x"), 16).unwrap();
        let slot = u32::from_str_radix(slot_re.find(&record[2]).unwrap().as_str(), 16).unwrap();
        result.push(ConflictInfo {
            kind: ConflictType::All,
            selector,
            slot: Some(slot),
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
        let slot = u32::from_str_radix(slot_re.find(&record[3]).unwrap().as_str(), 16).unwrap();
        result.push(ConflictInfo {
            kind: ConflictType::Var,
            selector,
            slot: Some(slot),
            value,
        });
    }
    let const_csv = path.join("Conflict_ConsConflict.csv");
    rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b'\t')
        .from_path(const_csv.as_path())
        .unwrap();
    for r in rdr.records() {
        let record = r.unwrap();
        let selector = u32::from_str_radix(record[1].trim_start_matches("0x"), 16).unwrap();
        let value = hex::decode(record[2].trim_start_matches("0x"))
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
    result
}

fn get_method_signature(method: &Map<String, Value>) -> String {
    let mut signature = String::from(method["name"].as_str().unwrap());
    signature.push_str("(");
    let inputs = method["inputs"].as_array().unwrap();
    for (i, input) in inputs.iter().enumerate() {
        let ty = input["type"].as_str().unwrap();
        if i != 0 {
            signature.push_str(",");
        }
        match ty {
            "tuple" => {
                signature.push_str("(");
                let tuple_inputs = input["components"].as_array().unwrap();
                for (j, tuple_input) in tuple_inputs.iter().enumerate() {
                    let ty = tuple_input["type"].as_str().unwrap();
                    signature.push_str(ty);
                    if j != tuple_inputs.len() - 1 {
                        signature.push_str(",");
                    }
                }
                signature.push_str(")");
            }
            _ => {
                signature.push_str(ty);
            }
        }
    }
    signature.push_str(")");
    signature
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
                method.insert("selector".into(), serde_json::to_value(method_id).unwrap());
            }
        });
    let new_abi = serde_json::to_string(&origin_abi).unwrap();
    std::fs::write(&args.abi, new_abi).unwrap();
}
