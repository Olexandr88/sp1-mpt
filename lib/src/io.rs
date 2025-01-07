use crate::{TrieEntry, TrieMultiProof};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// The input to the SP1 program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramInput {
    pub state_trie_root: B256,
    pub leaves: Vec<TrieEntry>,
    pub proof: TrieMultiProof,
}

/// Public values to be committed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicValuesStruct {
    pub state_trie_root: B256,
    pub leaves: Vec<TrieEntry>,
    pub success: bool,
}
