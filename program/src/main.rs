//! A SP1 program that verifies the MPT MultiProof for given list of accounts that are part of a
//! single state trie.

#![no_main]
sp1_zkvm::entrypoint!(main);

use mpt_verify_lib::{verify, ProgramInput, PublicValuesStruct};

pub fn main() {
    // Read an input to the program.
    let input = sp1_zkvm::io::read_vec();
    let input = bincode::deserialize::<ProgramInput>(&input).unwrap();
    let ProgramInput {
        state_trie_root,
        leaves,
        proof,
    } = input;

    verify(state_trie_root, &leaves, proof).unwrap();

    let public_values = PublicValuesStruct {
        state_trie_root,
        leaves,
        success: true,
    };

    // Encode the public values of the program.
    let bytes = bincode::serialize::<PublicValuesStruct>(&public_values).unwrap();

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
