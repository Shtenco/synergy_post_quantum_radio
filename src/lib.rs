//! SYNERGY Post-Quantum Radio.
//!
//! The protocol deliberately separates three security lanes:
//! 1. standards-based post-quantum cryptography, which is authoritative;
//! 2. quantum-teleportation evidence, which is backend-dependent;
//! 3. recovered PI-PQ provenance, which remains non-authoritative until the
//!    exact historical primitive is recovered and independently reviewed.

pub mod crypto;
pub mod pi_pq;
pub mod protocol;
pub mod quantum;
pub mod radio;

pub const PROTOCOL_VERSION: u16 = 1;
pub const NETWORK_DOMAIN: &[u8] = b"SYNERGY/PQ-RADIO/V1\0";
