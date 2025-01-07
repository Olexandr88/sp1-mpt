mod io;
mod mpt_verify;

use alloy::rpc::types::{Account, EIP1186AccountProofResponse};
use alloy_primitives::{keccak256, Bytes, B256};
use alloy_rlp::encode;
use alloy_trie::Nibbles;
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::iter;

use crate::mpt_verify::{verify_proof_stateful, VerifiedNodeStack};

pub use io::{ProgramInput, PublicValuesStruct};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrieMultiProof {
    branches: Vec<TrieBranch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrieEntry {
    pub key: B256,
    pub value: Vec<u8>,
}

pub type TrieBranch = Vec<Bytes>;

pub fn split_eip_1186_account_proof(
    account_proof: EIP1186AccountProofResponse,
) -> (TrieEntry, TrieBranch) {
    let key = keccak256(account_proof.address);
    let value = encode(Account {
        nonce: account_proof.nonce,
        balance: account_proof.balance,
        storage_root: account_proof.storage_hash,
        code_hash: account_proof.code_hash,
    });
    let entry = TrieEntry { key, value };
    (entry, account_proof.account_proof)
}

/// This is used to generate a MultiProof for a list of account proofs.
pub fn prove(mut leaves: Vec<(TrieEntry, TrieBranch)>) -> (Vec<TrieEntry>, TrieMultiProof) {
    leaves.sort_by_key(|(entry, _)| entry.key);
    let (entries, branches): (Vec<_>, Vec<_>) = leaves.into_iter().unzip();

    let branches = branches
        .into_iter()
        .scan(Vec::new(), |last_branch, branch| {
            let truncated_branch = branch
                .iter()
                .enumerate()
                .skip_while(|(i, node)| Some(node) == last_branch.get(*i).as_ref())
                .map(|(_, node)| node.clone())
                .collect();
            *last_branch = branch;
            Some(truncated_branch)
        })
        .collect::<Vec<_>>();

    (entries, TrieMultiProof { branches })
}

/// Actual MPT verification function that verifies the deduplicated nodes.
pub fn verify(root: B256, leaves: &[TrieEntry], proof: TrieMultiProof) -> Result<()> {
    if proof.branches.len() != leaves.len() {
        return Err(eyre::eyre!(
            "Proof shape does not match the number of leaves"
        ));
    }

    let mut stack = VerifiedNodeStack::default();
    for (leaf, branch) in iter::zip(leaves, &proof.branches) {
        verify_proof_stateful(
            root,
            Nibbles::unpack(leaf.key),
            Some(leaf.value.clone()),
            branch,
            &mut stack,
        )?;
    }
    Ok(())
}
