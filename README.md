# SP1 MPT Prover

MPT account inclusion verifier written on top of [SP1](https://github.com/succinctlabs/sp1).

## Requirements

- [Rust](https://rustup.rs/)
- [SP1](https://docs.succinct.xyz/getting-started/install.html)

## Running the Project

The included SP1 script program executes with the given input as well as prove (optionally compress)
and verify the MPT account inclusion program for your given input

### Execute the Program

We recommend using Rust native compilation for increased performance, simply set the environment variable
```sh
export RUSTFLAGS="-C target-cpu=native"
```

To run the program on a given set of account proofs

```sh
cargo run --release --bin mpt-prover -- --verification-info <MPT_ACCOUNTS_JSON_FILE> --state-trie-root <STATE_ROOT_TRIE>
```

This will execute the program and create three output files which contain serialized proof with
public values, proof without public values as well as the input to the SP1 program. 

By default we are using log level `info`, to get more verbose or less verbose input change `RUST_LOG=`
environment variable accordingly

We have included an example input json file `mainnet_21367805.json` which includes all the account proofs for
the block `21367805` that has the state trie root `0x1aa2e84e4e7b3c6d578a1ea46af8672ca64fdd908288332f8048bca13047d033`.
> [!WARNING]
> This can take upto 30 minutes to run depending on the device you are running. You may truncate this list to run in a managable time.

### Compress Proofs

Optionally you can compress the proofs for smaller proof sizes but longer proving time.

```sh
cargo run --release --bin mpt-prover -- --compress --verification-info <MPT_ACCOUNTS_JSON_FILE> --state-trie-root <STATE_ROOT_TRIE>
```

### GPU Acceleration
SP1 has [Cuda](https://developer.nvidia.com/cuda-toolkit) support and you can accelerate on GPU
to improve proving time, use the following feature to use Cuda prover

```sh
cargo run --release --bin mpt-prover --features cuda -- --compress --verification-info <MPT_ACCOUNTS_JSON_FILE> --state-trie-root <STATE_ROOT_TRIE>
```