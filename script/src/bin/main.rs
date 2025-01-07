//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! and have a core proof generated. This script parses the EIP-1186 account proofs and generates a
//! MultiProof for the mpt-verifier program to verify the account proofs.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use std::{fs::File, path::PathBuf};

use clap::Parser;
use mpt_prover_script::EIP1186AccountProofs;
use mpt_verify_lib::{
    prove, split_eip_1186_account_proof, ProgramInput, PublicValuesStruct, TrieBranch, TrieEntry,
};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const MPT_VERIFIER_ELF: &[u8] = include_elf!("mpt-verifier-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    state_trie_root: String,

    #[clap(long, default_value = "false")]
    // Whether to compress the proof or not.
    compress: bool,

    #[clap(long)]
    verification_info: PathBuf,
}

fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    // Initialize the logger.
    tracing_profile::init_tracing().unwrap();

    // Parse the command line arguments.
    let args = Args::parse();

    // Read the verification info.
    let verification_info = EIP1186AccountProofs::from_path(args.verification_info).unwrap();
    let trie_entries_and_branches = verification_info
        .0
        .into_iter()
        .map(split_eip_1186_account_proof)
        .collect::<Vec<(TrieEntry, TrieBranch)>>();
    let (entries, multi_proof) = prove(trie_entries_and_branches);
    println!("Proving mpt-verifier on {} accounts...", entries.len());

    println!(
        "Witness data is {} bytes",
        bincode::serialized_size(&multi_proof).unwrap()
    );

    let input = ProgramInput {
        state_trie_root: args.state_trie_root.parse().unwrap(),
        leaves: entries,
        proof: multi_proof,
    };

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    // Execute the program
    let (output, report) = client
        .execute(MPT_VERIFIER_ELF, stdin.clone())
        .run()
        .unwrap();
    println!("Program executed successfully.");

    // Read the output.
    let decoded = bincode::deserialize::<PublicValuesStruct>(output.as_slice()).unwrap();

    assert!(decoded.success);

    // Record the number of cycles executed.
    println!("Number of cycles: {}", report.total_instruction_count());
    print!("Report: {}", report);

    // Setup the program for proving.
    let (pk, vk) = client.setup(MPT_VERIFIER_ELF);

    bincode::serialize_into(
        File::create("stdin.bin").expect("failed to open file"),
        &stdin,
    )
    .expect("Failed to write stdin to file");

    // Generate the proof
    println!("Starting proof generation.");
    let proof = {
        let span = tracing::info_span!("SP1 proving");
        if args.compress {
            println!("Proving with compression");
            span.in_scope(|| {
                client
                    .prove(&pk, stdin)
                    .compressed()
                    .run()
                    .expect("Proving should work.")
            })
        } else {
            println!("Proving without compression");
            span.in_scope(|| {
                client
                    .prove(&pk, stdin)
                    .run()
                    .expect("Proving should work.")
            })
        }
    };
    proof
        .save("proof-with-pis.bin")
        .expect("saving proof failed");
    bincode::serialize_into(
        File::create("proof-without-pis.bin").expect("failed to open file"),
        &proof.proof,
    )
    .expect("saving proof without pis failed");

    println!("Proof generation finished.");

    // Verify the proof.
    {
        let span = tracing::info_span!("SP1 verifying");
        span.in_scope(|| {
            client
                .verify(&proof, &vk)
                .expect("proof verification should succeed");
        })
    }

    println!("Successfully verified proof!");
}
