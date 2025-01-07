use std::{fs::OpenOptions, io::Read, path::PathBuf};

use alloy::rpc::types::EIP1186AccountProofResponse;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EIP1186AccountProofs(pub Vec<EIP1186AccountProofResponse>);

impl EIP1186AccountProofs {
    pub fn from_path(path: PathBuf) -> eyre::Result<Self> {
        let mut file = OpenOptions::new().read(true).open(path)?;
        if !file.metadata()?.is_file() {
            return Err(eyre::eyre!("Failed to find AddressList file"));
        }
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let list: EIP1186AccountProofs = serde_json::from_str(&contents)?;
        Ok(list)
    }
}
