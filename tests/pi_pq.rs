use synergy_post_quantum_radio::pi_pq::PiPqEvidence;

#[test]
fn pi_pq_lane_is_fail_closed_until_historical_algorithm_is_recovered() {
    let evidence = PiPqEvidence { algorithm_source_hash: [1; 32], specification_hash: [2; 32], test_vector_root: [3; 32], input_commitment: [4; 32], output_commitment: [5; 32], version: 1 };
    assert!(evidence.evidence_root().is_some());
    assert!(!evidence.may_authorize_radio_session());
    assert!(!evidence.may_replace_standard_pqc());
}
