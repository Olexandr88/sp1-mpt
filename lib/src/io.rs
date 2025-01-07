use crate::{TrieEntry, TrieMultiProof};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramInput {
    pub state_trie_root: B256,
    pub leaves: Vec<TrieEntry>,
    pub proof: TrieMultiProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicValuesStruct {
    pub state_trie_root: B256,
    pub leaves: Vec<TrieEntry>,
    pub success: bool,
}
