# Cyclic Hash Computation with Plonky2

Have you ever thought to yourself, "Gee, I sure wish I could cryptographically prove in quantum-resistant zero knowledge that I computed a gigantic chain of hashes correctly"? Well _good news_ because this repo will fill that burning hole in your heart with a plonky2-based implementation of a prover/verifier pair for a recursive computation chain that argues the computational integrity of a series of hashes a la IVC style and outputs a compressed proof of constant size. The recursive nature of this circuit gives desireable scaling characteristics, and this work presents and effort to better understand the unique design challenges presented when working with low-level circuitry.

## Quick start:

You can download the repo and run the main branch with:
```bash
cargo test
```

Which is run in release mode by default. This repo requires the nightly Rust toolchain. If you are seeing errors related to:

```bash
6 | #![feature(specialization)]
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0554]: `#![feature]` may not be used on the stable release channel
  |
7 | #![cfg_attr(target_arch = "x86_64", feature(stdarch_x86_avx512))]
  |                                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0554]: `#![feature]` may not be used on the stable release channel
  |
7 | #![cfg_attr(target_arch = "x86_64", feature(stdarch_x86_avx512))]
  |                                             ^^^^^^^^^^^^^^^^^^
```

Then please double check your toolchain. You may need to run `rustup update nightly` and ensure the `rustc` component is installed. Otherwise, this repo should work out of the box.

You can also run:

```bash
RUSTFLAGS="-Ctarget-cpu=native" cargo run --release --example circuit_telemetry -- -vv --steps 20
```

To quickly benchmark prover and verifer performance, as well as examine details about the chain over a given number of steps:

```text
[2024-08-23T08:01:38Z INFO  hash_chain] Number of gates in circuit: 112960
[2024-08-23T08:01:46Z INFO  hash_chain] Total Proof length: 133440 bytes
[2024-08-23T08:01:46Z INFO  circuit_telemetry] Proof time: 9.733192095s
[2024-08-23T08:01:46Z INFO  circuit_telemetry] Verification time: 4.142599ms
[2024-08-23T08:01:46Z INFO  circuit_telemetry] Circuit depth: 20
```
## Supported Hashes:

The following hashes are available in the recursive chain:

| Hasher | Validation |
|----------|----------|
| Poseidon Hash    | [![Test Poseidon Hash](https://github.com/drcapybara/hash-chain/actions/workflows/test_poseidon_hash_chain.yml/badge.svg?branch=main)](https://github.com/drcapybara/hash-chain/actions/workflows/test_poseidon_hash_chain.yml) |
| Keccak    | [![Test Keccak Hash](https://github.com/drcapybara/hash-chain/actions/workflows/test_keccak_hash_chain.yml/badge.svg?branch=feat%2Fkeccak)](https://github.com/drcapybara/hash-chain/actions/workflows/test_keccak_hash_chain.yml) |

The keccak chain fails to build successfully at current, work is ongoing to fix this eventually.

# Strategy

Our approach is to insert the following gates into the circuit with the requisite connections. It is not enough to create a circuit that simply connects each hash output the next input, the prover must argue the hash computation _and_ verify the preceeding hash in a single step, taking into account the recursive structure of the chain:

```text
+--------------------------------+    +-------------------------+    +------------------------------+
| 1. initialize_circuit_builder  |    | 2. setup_hashes         |    | 3. common_data_for_recursion |
|    Set up the circuit builder  |──▶| Configure initial       |──▶| Set up data for recursion    |
|     and configuration.         |    |  and current hash       |    | and verifier data inputs.    |
+--------------------------------+    | targets and register    |    +------------------------------+                            
          |                           | them as public inputs.  |              |
          |                           +-------------------------+              |
          │                                                                    │
          │            +--------------------+                                  │
          └──────────▶| 4. setup_condition |                                  │
                       |  Set condition for |                                  │
                       |  recursion base.   |                                  │
                       +--------------------+                                  │
                                 │                                             ▼
                                 │            +--------------------------------------+      
                                 └──────────▶|       5. setup_recursive_layers      |
                                              |        Configure recursive layers    |
                                              |        and integrate proof.          |
                                              +--------------------------------------+
                                                    │                      ▲
                                                    │                      │
                                                    │                      │
                                                    ▼                      │
                                          +-----------------------------+  │
                                          | 6. evaluate_recursive_circuit|──┘
                                          |  Handle recursion, verify,  |
                                          |  and loop through steps.     |
                                          +-----------------------------+
                                                    │
                                                    ▼
                                          +-------------------------+
                                          | 7. compile_and_process  |
                                          |  Finalize circuit and   |
                                          |  handle processing.     |
                                          +-------------------------+
```
You can also view a rough sketch of a circuit diagram of the entire setup:
![](https://github.com/user-attachments/assets/0d7e9a9a-a1c3-4b5e-95fd-1dbe812d1076)


### Initial Setup
- **Counter Initialization**: A counter gate is initialized to track the depth of recursion. The counter starts at 1 after the base case performs the first hash iteration.
- **Hash Initialization**: A virtual hash target gate is inserted and registered as a public input, marking the starting point of the hash chain. The initial hash is set to the zero hash `[F::ZERO; 4]` (all zeros).
- **Hash Gate**: An updateable hash gate is added to enable hash updates as the recursion progresses. The circuit computes `current_hash_out = hash(current_hash_in)`, where `current_hash_in` is either the initial hash (base case) or the previous proof's output hash (recursive case).

### Recursive Hashing
- **Verifier Data Setup**: Circuit common data is prepared, including configuration and partial witnesses required for recursion. This sets up the recursive proof structure using plonky2's cyclic recursion capabilities.
- **Base Case Identification**: A condition flag is set to identify whether the current computation is the base case (`condition=false`) or a recursive case (`condition=true`). In the base case, the hash chain starts with the zero hash. In recursive cases, each proof verifies the previous proof and extends the chain.
- **Hash Chain Connection**: The current hash input is connected to either the previous proof's output hash (when `condition=true`) or the initial hash (when `condition=false`). The circuit ensures proper chaining by verifying the inner cyclic proof and computing the next hash in the sequence.

### Recursive Proof Verification
- **Circuit Building**: The circuit for the current step is built with all necessary gates and constraints. The circuit structure remains constant regardless of the number of steps, enabling constant-size proofs.
- **Proof Generation**: A proof of the correctness of the current hash computation is generated using the circuit data. Each recursive step produces a new proof that verifies the previous proof and extends the hash chain by one iteration.
- **Proof Verification**: The generated proof is verified to ensure that the hash was computed correctly. The verification process checks both the proof's validity and that the hash chain was computed correctly by comparing against the expected hash value.

### Final Verification
- **Final Hash Check**: After all recursive steps, the final hash is compared against the expected result to confirm the integrity of the entire hash chain. The `verify` function checks that `current_hash == hash^counter(initial_hash)` by iteratively hashing the initial hash `counter` times and comparing the result. This provides an additional validation beyond the proof verification itself.

## Usage:

```rust
use hash_chain::HashChain;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig; // A config with poseidon as the hasher for FRI
type F = <C as GenericConfig<D>>::F;

// a non-ZK config, commitments and proof may reveal input data
let config = CircuitConfig::standard_recursion_config(); 
let mut circuit = CircuitBuilder::<F, D>::new(config.clone());

// Prove
let (proof, circuit_data) =
    <CircuitBuilder<GoldilocksField, D> as HashChain<GoldilocksField, D, C>>::build_hash_chain_circuit(
        &mut circuit,
        2, // number of steps in the hash chain
    )
    .unwrap();

// Verify
let verification_result =
    <CircuitBuilder<GoldilocksField, D> as HashChain<GoldilocksField, D, C>>::verify(proof, &circuit_data);
assert!(verification_result.is_ok());
```

We observe a total uncompressed proof size of 133440 bytes, regardless of number of steps in the chain. We find this is very nice because this number stays the same no matter how many hashes we compute. In theory, recursively verifiable proofs of this nature can compress extremely large computations into a very small space. Think fully-succinct blockchains, in which light clients can verify the entire state of the chain trustlessly by verifying a small and simple proof in trivial amounts of time.

### Public Inputs Structure

The proof's public inputs follow this structure:
- `[0..4]`: Initial hash (4 field elements) - remains constant throughout the chain, set to `[F::ZERO; 4]`
- `[4..8]`: Current hash (4 field elements) - the hash after `counter` iterations
- `[8]`: Counter (1 field element) - the number of hash iterations performed (starts at 1, increments by 1 each recursive step)
- `[9..]`: Verifier data (variable length) - plonky2's verifier circuit data

The verification function validates that `current_hash == hash^counter(initial_hash)`, ensuring the hash chain was computed correctly.

## Benches

This crate uses criterion for formal benchmarks. Bench prover and verifier performance with:

```bash
cargo bench
```
Here are some preliminary performance metrics observed on Apple M4 Pro (Darwin):

| Circuit depth (steps) | Prover Runtime (s) | Verifier Runtime (ms)|
|-----------------------|--------------------|----------------------|
| 2                     | 2.629 s            | 2.474 ms             |
| 4                     | 3.163 s            | 2.454 ms             |
| 8                     | 4.196 s            | 2.491 ms             |
| 16                    | 6.474 s            | 2.498 ms             |
| 32                    | 10.77 s            | 2.496 ms             |
| 64                    | 18.78 s            | 2.518 ms             |

**Key Observation**: Verifier runtime remains constant (~2.5ms) regardless of chain length, demonstrating the succinctness property of recursive proofs. Prover time scales roughly linearly with the number of steps.


## Acknowledgments

This project makes use of the following open-source libraries:

Recursive STARK Wiring framework:
- **[plonky2](https://github.com/drcapybara/plonky2)** by Polygon Labs 


Hash Circuits:
- **[plonky2_crypto](https://github.com/JumpCrypto/plonky2-crypto)** by Jump Crypto 

## Readings
- [Plonky2 whitepaper](https://github.com/0xPolygonZero/plonky2/blob/main/plonky2/plonky2.pdf)

- The always excellent [Anatomy of a STARK](https://aszepieniec.github.io/stark-anatomy/):


## TODO
- [x] add benches
- [x] better error handling with thiserr
- [ ] Compress the proof at the end
- [ ] support keccak
- [ ] add richer circuit telemetry
