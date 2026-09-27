use synergy_post_quantum_radio::crypto::PqIdentity;
use synergy_post_quantum_radio::protocol::{accept_server, finish_client, finish_server, start_client, RadioCapabilities};
use synergy_post_quantum_radio::quantum::{QubitState, QuantumTeleportationBackend, SimulatedTeleportationBackend};

fn radio() -> RadioCapabilities {
    RadioCapabilities { frequency_hz: 915_000_000, bandwidth_hz: 125_000, modem: "SIM-LORA".to_string() }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = PqIdentity::generate()?;
    let bob = PqIdentity::generate()?;
    let mut teleport = SimulatedTeleportationBackend::default();
    let receipt = teleport.teleport(&QubitState::plus_i())?;
    let client = start_client(&alice, 1, radio(), Some(&receipt), None)?;
    let server = accept_server(&bob, &client.hello, radio(), Some(&receipt), None)?;
    let (finish, mut alice_session) = finish_client(&alice, &client, &server.authenticated_hello)?;
    let mut bob_session = finish_server(&server, &client.hello, &finish)?;
    let frame = alice_session.encrypt([0xA5; 32], b"SYNERGY PQ RADIO: HELLO")?;
    let plaintext = bob_session.decrypt(&frame)?;
    println!("protocol_version=1");
    println!("teleportation_backend=SIMULATION");
    println!("teleportation_fidelity_ppb={}", receipt.fidelity_ppb);
    println!("pq_auth=ML-DSA-87+SLH-DSA-SHAKE-256s");
    println!("pq_kem=dual ML-KEM-1024");
    println!("aead=ChaCha20-Poly1305");
    println!("received={}", String::from_utf8_lossy(&plaintext));
    println!("physical_quantum_claim=false");
    Ok(())
}
