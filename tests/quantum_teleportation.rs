use synergy_post_quantum_radio::quantum::{QubitState, QuantumBackendMode, QuantumTeleportationBackend, SimulatedTeleportationBackend};

#[test]
fn all_four_bell_measurement_outcomes_reconstruct_state() {
    let source = QubitState::plus_i();
    for q0 in 0..=1 {
        for q1 in 0..=1 {
            let bell_pair_id = [1 + q0 * 2 + q1; 32];
            let (destination, receipt) = SimulatedTeleportationBackend::teleport_with_measurements(&source, q0, q1, bell_pair_id).expect("teleportation");
            assert!(source.fidelity(&destination) > 1.0 - 1e-12);
            assert_eq!(receipt.fidelity_ppb, 1_000_000_000);
            assert_eq!(receipt.mode, QuantumBackendMode::Simulation);
            assert!(!receipt.may_strengthen_physical_security_claim());
        }
    }
}

#[test]
fn simulation_receipt_is_bound_but_never_claimed_as_hardware() {
    let source = QubitState::plus();
    let mut backend = SimulatedTeleportationBackend::default();
    let receipt = backend.teleport(&source).expect("teleportation");
    assert!(receipt.root().is_some());
    assert!(!receipt.may_strengthen_physical_security_claim());
}


#[test]
fn hardware_backend_requires_attested_physical_evidence() {
    use synergy_post_quantum_radio::quantum::{
        AttestedHardwareTeleportationBackend, HardwareQuantumDriver,
        HardwareTeleportationMeasurement,
    };

    struct FakeHardware;

    impl HardwareQuantumDriver for FakeHardware {
        fn teleport_physical(
            &mut self,
            source: &QubitState,
        ) -> Result<HardwareTeleportationMeasurement, &'static str> {
            Ok(HardwareTeleportationMeasurement {
                bell_pair_id: [9; 32],
                alice_measurement_q0: 0,
                alice_measurement_q1: 0,
                source_state_commitment: source.commitment(),
                destination_state_commitment: source.commitment(),
                fidelity_ppb: 999_000_000,
                hardware_attestation_root: [7; 32],
            })
        }
    }

    let mut backend = AttestedHardwareTeleportationBackend::new(FakeHardware);
    let receipt = backend.teleport(&QubitState::plus()).expect("hardware receipt");
    assert_eq!(receipt.mode, QuantumBackendMode::Hardware);
    assert_eq!(receipt.hardware_attestation_root, Some([7; 32]));
    assert!(receipt.may_strengthen_physical_security_claim());
}
