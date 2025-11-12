use log::info;
use plonky2::{
    field::extension::Extendable,
    gates::noop::NoopGate,
    hash::{
        hash_types::{HashOutTarget, RichField},
        hashing::hash_n_to_hash_no_pad,
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::{
        cyclic_recursion::check_cyclic_proof_verifier_data, dummy_circuit::cyclic_base_proof,
    },
    util::serialization::DefaultGateSerializer,
};
use std::array::TryFromSliceError;
pub const KECCAK256_R: usize = 1088;

use anyhow::Error as AnyhowError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HashChainError {
    #[error("{0}")]
    AnyhowError(#[from] AnyhowError),
    #[error("Failed to convert slice: {0}")]
    SliceConversionError(#[from] TryFromSliceError),
}

// Result type for operations that produce a target proof with public inputs
// including an error handling mechanism specific to hash chain operations.
type ProofTargetResult<const D: usize> = Result<ProofWithPublicInputsTarget<D>, HashChainError>;

// Simplifies referencing the proof structure with generics, facilitating
// easier usage within functions and trait methods across different configurations.
type Proof<F, C, const D: usize> = ProofWithPublicInputs<F, C, D>;

// Alias for circuit data that simplifies references to circuit structures within various methods.
// It describes the circuit to be proven and can be used during verification.
type CircuitMap<F, C, const D: usize> = CircuitData<F, C, D>;

// Provides a simplified reference to common circuit data structures
type CommonData<F, const D: usize> = CommonCircuitData<F, D>;

// Tuple type that combines both proof and circuit data
type ProofAndCircuit<F, C, const D: usize> = (Proof<F, C, D>, CircuitMap<F, C, D>);

// Result type for operations that either successfully return a combined proof
// and circuit data or an error specific to hash chain processing.
type ProofAndCircuitResult<F, C, const D: usize> = Result<ProofAndCircuit<F, C, D>, HashChainError>;

#[allow(clippy::too_many_arguments)]
pub trait HashChain<F: RichField + Extendable<D>, const D: usize, C: GenericConfig<D, F = F>> {
    fn build_hash_chain_circuit(&mut self, steps: usize) -> ProofAndCircuitResult<F, C, D>;
    fn setup_recursive_layers(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        common_data: CommonData<F, D>,
        initial_hash_target: HashOutTarget,
        condition: BoolTarget,
        current_hash_in: HashOutTarget,
        one: Target,
        counter: Target,
    ) -> ProofTargetResult<D>;

    fn verify(
        proof: Proof<F, C, D>,
        cyclic_circuit_data: &CircuitMap<F, C, D>,
    ) -> Result<(), HashChainError>;

    fn prove_current_layer(
        condition: BoolTarget,
        inner_cyclic_proof_with_pub_inputs: ProofWithPublicInputsTarget<D>,
        proof: Proof<F, C, D>,
        verifier_data_target: VerifierCircuitTarget,
        cyclic_circuit_data: &CircuitMap<F, C, D>,
        initial_hash_target: HashOutTarget,
        current_hash_out: HashOutTarget,
        counter: Target,
    ) -> Result<Proof<F, C, D>, HashChainError>;

    fn configure_layers() -> CommonData<F, D>;

    fn evaluate_recursive_circuit(
        condition: BoolTarget,
        inner_cyclic_proof_with_pub_inputs: ProofWithPublicInputsTarget<D>,
        common_data: CommonData<F, D>,
        cyclic_circuit_data: CircuitMap<F, C, D>,
        verifier_data_target: VerifierCircuitTarget,
        initial_hash_target: HashOutTarget,
        current_hash_out: HashOutTarget,
        counter: Target,
        steps: usize,
    ) -> ProofAndCircuitResult<F, C, D>;
}

impl<F: RichField + Extendable<D>, const D: usize, C: GenericConfig<D, F = F> + 'static>
    HashChain<F, D, C> for CircuitBuilder<F, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    /// Implementation strategy:
    ///
    /// ```text
    /// +--------------------------------+    +-------------------------+    +------------------------------+
    /// | 1. initialize_circuit_builder  |    | 2. setup_hashes         |    | 3. common_data_for_recursion |
    /// |    Set up the circuit builder  |──▶| Configure initial       |──▶| Set up data for recursion    |
    /// |     and configuration.         |    |  and current hash       |    | and verifier data inputs.    |
    /// +--------------------------------+    | targets and register    |    +------------------------------+                            
    ///           |                           | them as public inputs.  |              |
    ///           |                           +-------------------------+              |
    ///           │                                                                    │
    ///           │            +--------------------+                                  │
    ///           └──────────▶| 4. setup_condition |                                  │
    ///                        |  Set condition for |                                  │
    ///                        |  recursion base.   |                                  │
    ///                        +--------------------+                                  │
    ///                                  │                                             ▼
    ///                                  │            +--------------------------------------+      
    ///                                  └──────────▶|       5. setup_recursive_layers      |
    ///                                               |        Configure recursive layers    |
    ///                                               |        and integrate proof.          |
    ///                                               +--------------------------------------+
    ///                                                     │                      ▲
    ///                                                     │                      │
    ///                                                     │                      │
    ///                                                     ▼                      │
    ///                                           +-----------------------------+  │
    ///                                           | 6. process_recursive_layer  |──┘
    ///                                           |  Handle recursion, verify,  |
    ///                                           |  and loop through steps.    |
    ///                                           +-----------------------------+
    ///                                                     │
    ///                                                     ▼
    ///                                           +-------------------------+
    ///                                           | 7. compile_and_process  |
    ///                                           |  Finalize circuit and   |
    ///                                           |  handle processing.     |
    ///                                           +-------------------------+
    /// ```
    ///
    /// Following this approach, we can build a properly constrained recursive hash chain
    /// circuit. The implementation uses plonky2's cyclic recursion to create a constant-size
    /// proof that verifies an arbitrary number of hash iterations.
    ///
    /// ## Usage
    /// ```
    /// use hash_chain::HashChain;
    /// use plonky2::{
    ///     field::goldilocks_field::GoldilocksField,
    ///     plonk::{
    ///         circuit_builder::CircuitBuilder,
    ///         circuit_data::CircuitConfig,
    ///         config::{GenericConfig, PoseidonGoldilocksConfig},
    ///     },
    /// };
    ///
    /// const D: usize = 2;
    /// type C = PoseidonGoldilocksConfig; // A config with poseidon as the hasher for FRI
    /// type F = <C as GenericConfig<D>>::F;
    ///
    /// // a non-ZK config, commitments and proof may reveal input data
    /// let config = CircuitConfig::standard_recursion_config();
    /// let mut circuit = CircuitBuilder::<F, D>::new(config.clone());
    ///
    /// // Prove
    /// let (proof, circuit_data) =
    ///     <CircuitBuilder<GoldilocksField, D> as HashChain<GoldilocksField, D, C>>::build_hash_chain_circuit(
    ///         &mut circuit,
    ///         2, // number of steps in the hash chain
    ///     )
    ///     .unwrap();
    ///
    /// // Verify
    /// let verification_result =
    ///     <CircuitBuilder<GoldilocksField, D> as HashChain<GoldilocksField, D, C>>::verify(proof, &circuit_data);
    /// assert!(verification_result.is_ok());
    /// ```
    ///
    /// Remark: This function is probably too big and could use some modularization.
    /// Because it is so heavily parameterized over generics, refactoring becomes difficult
    /// when needing to pass around the builder between various functions (which we probably shouldnt be doing).
    fn build_hash_chain_circuit(
        &mut self,
        steps: usize,
    ) -> Result<(ProofWithPublicInputs<F, C, D>, CircuitData<F, C, D>), HashChainError> {
        let config = CircuitConfig::standard_recursion_config();

        // Setup the builder for the cyclic circuit. We will proceed to add the necessary
        // gates into this first builder, then proceed to construct additional builders
        // and configs for each layer of recursion.
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Set a counter to be incremented and track recursion depth
        let one = builder.one();

        // Setup the initial hash target gate and register the initial hash as a public input.
        let initial_hash_target: HashOutTarget = builder.add_virtual_hash();
        builder.register_public_inputs(&initial_hash_target.elements);

        // Insert an updateable hash gate into the circuit, so that we can
        // update it as we recurse.
        let current_hash_in: HashOutTarget = builder.add_virtual_hash();
        let current_hash_out: HashOutTarget =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(current_hash_in.elements.to_vec());

        builder.register_public_inputs(&current_hash_out.elements);
        let counter = builder.add_virtual_public_input();

        // Get the `CircuitCommonData` for this circuit, which defines the configuration
        // and partial witnesses for the recursion layers.
        let mut common_data = <CircuitBuilder<F, D> as HashChain<F, D, C>>::configure_layers();

        // Define the verifier data target for the circuit.
        let verifier_data_target = builder.add_verifier_data_public_inputs();
        common_data.num_public_inputs = builder.num_public_inputs();
        let gate_serializer = DefaultGateSerializer;
        let common_data_bytes = common_data
            .to_bytes(&gate_serializer)
            .map_err(|_| anyhow::Error::msg("CommonCircuitData serialization failed."))?;
        info!(
            "Common circuit data length: {} bytes",
            common_data_bytes.len()
        );

        info!(
            "Initial {} degree {} = 2^{}",
            "proof",
            common_data.degree(),
            common_data.degree_bits()
        );

        // Set a condition flag to determine if we are in the base case or not.
        let condition = builder.add_virtual_bool_target_safe();

        let inner_cyclic_proof_with_pub_inputs =
            <CircuitBuilder<F, D> as HashChain<F, D, C>>::setup_recursive_layers(
                self,
                &mut builder,
                common_data.clone(),
                initial_hash_target,
                condition,
                current_hash_in,
                one,
                counter,
            )?;

        info!(
            "Number of gates in circuit: {}",
            builder.num_gates() * steps
        );
        // We now have all of the appropriate layers setup, so
        // now lets compile the circuit.
        let cyclic_circuit_data = builder.build::<C>();

        // Enter recursive loop
        Self::evaluate_recursive_circuit(
            condition,
            inner_cyclic_proof_with_pub_inputs,
            common_data,
            cyclic_circuit_data,
            verifier_data_target,
            initial_hash_target,
            current_hash_out,
            counter,
            steps,
        )
    }

    // Setup the recursive hashes structure by establishing the size of the inputs and outputs
    // and connecting them to each other appropriately. Additionally setup the conditional proof
    // verification depending on whether we are in the base layer or not.
    //
    // The circuit connects:
    // - initial_hash_target to inner_cyclic_initial_hash (ensures initial hash stays constant)
    // - current_hash_in to either inner_cyclic_latest_hash (if condition=true) or initial_hash_target (if condition=false)
    // - counter to condition * inner_cyclic_counter + 1 (increments counter when condition=true)
    // This ensures proper hash chaining: each recursive step uses the previous proof's output hash as input.
    fn setup_recursive_layers(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        common_data: CommonCircuitData<F, D>,
        initial_hash_target: HashOutTarget,
        condition: BoolTarget,
        current_hash_in: HashOutTarget,
        one: Target,
        counter: Target,
    ) -> Result<ProofWithPublicInputsTarget<D>, HashChainError> {
        let inner_cyclic_proof_with_pub_inputs = builder.add_virtual_proof_with_pis(&common_data);
        let inner_cyclic_pub_inputs = &inner_cyclic_proof_with_pub_inputs.public_inputs;
        let inner_cyclic_initial_hash = HashOutTarget::try_from(&inner_cyclic_pub_inputs[0..4])?;
        let inner_cyclic_latest_hash = HashOutTarget::try_from(&inner_cyclic_pub_inputs[4..8])?;
        let inner_cyclic_counter = inner_cyclic_pub_inputs[8];
        builder.connect_hashes(initial_hash_target, inner_cyclic_initial_hash);
        let actual_hash_in =
            builder.select_hash(condition, inner_cyclic_latest_hash, initial_hash_target);
        builder.connect_hashes(current_hash_in, actual_hash_in);
        let new_counter = builder.mul_add(condition.target, inner_cyclic_counter, one);
        builder.connect(counter, new_counter);
        builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
            condition,
            &inner_cyclic_proof_with_pub_inputs,
            &common_data,
        )?;
        builder.print_gate_counts(0);
        Ok(inner_cyclic_proof_with_pub_inputs)
    }

    // Generates the common circuit data config for recursion, starting with the base case,
    // then generating the configs for the recursive cases.
    fn configure_layers() -> CommonCircuitData<F, D> {
        let config = CircuitConfig::standard_recursion_config();
        let builder = CircuitBuilder::<F, D>::new(config);
        let data = builder.build::<C>();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        let verifier_data =
            builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
        let data = builder.build::<C>();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        let verifier_data =
            builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);

        // Im not entiirely sure why we do this, but my best guess is that FRI requires AIR traces that are powers of 2.
        // So this step ensures that the builder always has a gate count that is a power of 2.
        while builder.num_gates() < 1 << 12 {
            builder.add_gate(NoopGate, vec![]);
        }

        builder.build::<C>().common
    }

    // This evaluates the current layer and produces a proof that this evaluation
    // is correct.
    fn prove_current_layer(
        condition: BoolTarget,
        inner_cyclic_proof_with_pub_inputs: ProofWithPublicInputsTarget<D>,
        proof: ProofWithPublicInputs<F, C, D>,
        verifier_circuit_target: VerifierCircuitTarget,
        cyclic_circuit_data: &CircuitData<F, C, D>,
        initial_hash_target: HashOutTarget,
        _current_hash_out: HashOutTarget,
        counter: Target,
    ) -> Result<ProofWithPublicInputs<F, C, D>, HashChainError> {
        let mut pw = PartialWitness::new();
        pw.set_bool_target(condition, true);
        pw.set_proof_with_pis_target(&inner_cyclic_proof_with_pub_inputs, &proof);
        pw.set_verifier_data_target(&verifier_circuit_target, &cyclic_circuit_data.verifier_only);

        // Set the public inputs from the previous proof to ensure proper chaining
        // Public inputs structure: [initial_hash (4), current_hash (4), counter (1), ...verifier_data...]
        // Note: The circuit connects these via setup_recursive_layers, but we need to set
        // the initial values to match the previous proof's outputs
        let prev_initial_hash = &proof.public_inputs[0..4];
        let prev_counter = proof.public_inputs[8];

        // Set initial hash (should remain constant across all iterations)
        for (i, &element) in prev_initial_hash.iter().enumerate() {
            pw.set_target(initial_hash_target.elements[i], element);
        }

        // Set counter to match what the circuit will compute
        // The circuit computes: counter = condition * inner_counter + 1
        // Since condition=true, this becomes: counter = inner_counter + 1
        // We need to set it to prev_counter + 1 to match the circuit's computation
        let one = F::ONE;
        pw.set_target(counter, prev_counter + one);

        // Note: current_hash_out is computed by the circuit from current_hash_in,
        // which is connected to inner_cyclic_latest_hash from the previous proof.
        // We don't need to set it explicitly - the circuit handles the chaining.

        let proof = cyclic_circuit_data.prove(pw)?;
        check_cyclic_proof_verifier_data(
            &proof,
            &cyclic_circuit_data.verifier_only,
            &cyclic_circuit_data.common,
        )?;
        Ok(proof)
    }

    // 1. If we are in the base layer, do not evaluate the previous layer.
    // 2. Prove the current layer, then move to the recursive case.
    // 3. Verify the previous layer, then prove this verification was successful.
    // 4. Recurse and verify
    fn evaluate_recursive_circuit(
        condition: BoolTarget,
        inner_cyclic_proof_with_pub_inputs: ProofWithPublicInputsTarget<D>,
        common_data: CommonCircuitData<F, D>,
        cyclic_circuit_data: CircuitData<F, C, D>,
        verifier_data_target: VerifierCircuitTarget,
        initial_hash_target: HashOutTarget,
        current_hash_out: HashOutTarget,
        counter: Target,
        steps: usize,
    ) -> Result<(ProofWithPublicInputs<F, C, D>, CircuitData<F, C, D>), HashChainError> {
        // Setup the partial witness for the proof, and set the
        // initial public input wires with actual hash values
        // Use zero hash as the starting point (all zeros)
        let mut pw = PartialWitness::new();
        let initial_hash: [F; 4] = [F::ZERO; 4];

        // Set the initial hash in the witness (starting point of the chain)
        for (i, &element) in initial_hash.iter().enumerate() {
            pw.set_target(initial_hash_target.elements[i], element);
        }

        // Compute the first hash (base case: hash the initial hash once)
        let first_hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&initial_hash);

        // Set counter to 1 (we've done one hash iteration)
        // Note: current_hash_out will be computed by the circuit from current_hash_in
        // In the base case (condition=false), current_hash_in = initial_hash_target
        // So current_hash_out = hash(initial_hash) = first_hash
        let one = F::ONE;
        pw.set_target(counter, one);

        // Set the condition wire to false because we are not in the recursive case
        // initially
        pw.set_bool_target(condition, false);

        // Create base proof with proper public inputs: [initial_hash (4), current_hash (4), counter (1)]
        let mut base_pub_inputs = Vec::new();
        base_pub_inputs.extend_from_slice(&initial_hash);
        base_pub_inputs.extend_from_slice(&first_hash.elements);
        base_pub_inputs.push(one);
        let base_pub_inputs_map: hashbrown::HashMap<usize, F> =
            base_pub_inputs.into_iter().enumerate().collect();

        pw.set_proof_with_pis_target::<C, D>(
            &inner_cyclic_proof_with_pub_inputs,
            &cyclic_base_proof(
                &common_data,
                &cyclic_circuit_data.verifier_only,
                base_pub_inputs_map,
            ),
        );

        info!(
            "Initial {} degree {} = 2^{}",
            "proof",
            common_data.degree(),
            common_data.degree_bits()
        );

        // Setup the expected data for the verifier
        pw.set_verifier_data_target(&verifier_data_target, &cyclic_circuit_data.verifier_only);
        let mut proof = cyclic_circuit_data.prove(pw)?;
        check_cyclic_proof_verifier_data(
            &proof,
            &cyclic_circuit_data.verifier_only,
            &cyclic_circuit_data.common,
        )?;
        cyclic_circuit_data.verify(proof.clone())?;

        // Base case of the recursion - now prove with condition=true to start recursive chaining
        proof = Self::prove_current_layer(
            condition,
            inner_cyclic_proof_with_pub_inputs.clone(),
            proof,
            verifier_data_target.clone(),
            &cyclic_circuit_data,
            initial_hash_target,
            current_hash_out,
            counter,
        )?;
        cyclic_circuit_data.verify(proof.clone())?;

        // Subsequent recursive steps - each step chains the previous hash
        for _ in 0..steps {
            proof = Self::prove_current_layer(
                condition,
                inner_cyclic_proof_with_pub_inputs.clone(),
                proof,
                verifier_data_target.clone(),
                &cyclic_circuit_data,
                initial_hash_target,
                current_hash_out,
                counter,
            )?;
        }

        Ok((proof, cyclic_circuit_data))
    }

    // Verify a proof given a circuit. This step is carried out by
    // a verifying party. This circuit is not currently configured
    // for zero-knowledge and should not be considered private.
    fn verify(
        proof: ProofWithPublicInputs<F, C, D>,
        cyclic_circuit_data: &CircuitData<F, C, D>,
    ) -> Result<(), HashChainError> {
        // Use the given hash permutation from plonky2 to verify
        // that the repeated hash is computed correctly.
        let initial_hash = &proof.public_inputs[..4];
        let hash = &proof.public_inputs[4..8];
        let counter = proof.public_inputs[8];

        // The verifier would not do this.
        // verification of the proof is sufficient to be
        // convinced with high probablity that the proof
        // is correct, this is merely done to validate
        // the circuit output.
        let expected_hash: [F; 4] = iterate_hash(
            initial_hash.try_into()?,
            counter.to_canonical_u64() as usize,
        );
        assert_eq!(hash, expected_hash);

        // Check the size of the proof; this number should remain
        // the same regardless of the number of steps in the
        // recursive circuit.
        let proof_bytes = proof.to_bytes();
        info!("Total Proof length: {} bytes", proof_bytes.len());
        Ok(cyclic_circuit_data.verify(proof)?)
    }
}

// Iterate a hash n number of times for validation purposes.
fn iterate_hash<F: RichField>(initial_state: [F; 4], n: usize) -> [F; 4] {
    let mut current = initial_state;
    for _ in 0..n {
        current = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&current).elements;
    }
    current
}

#[cfg(test)]
mod tests {

    use crate::HashChain;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    #[test]
    fn test_hash_chain() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut circuit = CircuitBuilder::<F, D>::new(config.clone());
        let (proof, circuit_map) = <CircuitBuilder<GoldilocksField, D> as HashChain<
            GoldilocksField,
            D,
            C,
        >>::build_hash_chain_circuit(&mut circuit, 128)
        .unwrap();

        let result =
            <CircuitBuilder<GoldilocksField, D> as HashChain<GoldilocksField, D, C>>::verify(
                proof,
                &circuit_map,
            );
        assert!(result.is_ok())
    }
}
