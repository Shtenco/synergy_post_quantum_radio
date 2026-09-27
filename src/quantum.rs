use num_complex::Complex64;
use rand::RngCore;
use sha2::{Digest, Sha256};

const EPSILON: f64 = 1e-12;
pub const MIN_HARDWARE_FIDELITY_PPB: u64 = 990_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantumBackendMode {
    Simulation,
    Hardware,
}

impl QuantumBackendMode {
    fn code(self) -> u8 {
        match self {
            Self::Simulation => 1,
            Self::Hardware => 2,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QubitState {
    pub alpha: Complex64,
    pub beta: Complex64,
}

impl QubitState {
    pub fn new(alpha: Complex64, beta: Complex64) -> Result<Self, &'static str> {
        let norm = alpha.norm_sqr() + beta.norm_sqr();
        if !norm.is_finite() || (norm - 1.0).abs() > 1e-9 {
            return Err("qubit state must be normalized");
        }
        Ok(Self { alpha, beta })
    }

    pub fn plus() -> Self {
        let a = 1.0 / 2.0_f64.sqrt();
        Self {
            alpha: Complex64::new(a, 0.0),
            beta: Complex64::new(a, 0.0),
        }
    }

    pub fn plus_i() -> Self {
        let a = 1.0 / 2.0_f64.sqrt();
        Self {
            alpha: Complex64::new(a, 0.0),
            beta: Complex64::new(0.0, a),
        }
    }

    pub fn fidelity(&self, other: &Self) -> f64 {
        let inner = self.alpha.conj() * other.alpha + self.beta.conj() * other.beta;
        inner.norm_sqr().clamp(0.0, 1.0)
    }

    pub fn commitment(&self) -> [u8; 32] {
        let canonical = canonical_global_phase(*self);
        let mut h = Sha256::new();
        h.update(b"SYNERGY/PQ-RADIO/QUBIT/V1\0");
        h.update(canonical.alpha.re.to_be_bytes());
        h.update(canonical.alpha.im.to_be_bytes());
        h.update(canonical.beta.re.to_be_bytes());
        h.update(canonical.beta.im.to_be_bytes());
        h.finalize().into()
    }
}

fn canonical_global_phase(state: QubitState) -> QubitState {
    let pivot = if state.alpha.norm() > EPSILON {
        state.alpha
    } else {
        state.beta
    };
    if pivot.norm() <= EPSILON {
        return state;
    }
    let phase = pivot / Complex64::new(pivot.norm(), 0.0);
    QubitState {
        alpha: state.alpha / phase,
        beta: state.beta / phase,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeleportationReceipt {
    pub mode: QuantumBackendMode,
    pub bell_pair_id: [u8; 32],
    pub alice_measurement_q0: u8,
    pub alice_measurement_q1: u8,
    pub source_state_commitment: [u8; 32],
    pub destination_state_commitment: [u8; 32],
    pub fidelity_ppb: u64,
    /// Nonzero only for a real hardware backend. It commits to device identity,
    /// calibration, experiment id and the backend's signed/raw evidence bundle.
    pub hardware_attestation_root: Option<[u8; 32]>,
}

impl TeleportationReceipt {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.bell_pair_id == [0; 32] {
            return Err("Bell-pair id required");
        }
        if self.alice_measurement_q0 > 1 || self.alice_measurement_q1 > 1 {
            return Err("teleportation measurements must be bits");
        }
        if self.source_state_commitment == [0; 32] || self.destination_state_commitment == [0; 32] {
            return Err("teleportation state commitments required");
        }
        if self.fidelity_ppb > 1_000_000_000 {
            return Err("invalid teleportation fidelity");
        }
        match self.mode {
            QuantumBackendMode::Simulation => {
                if self.hardware_attestation_root.is_some() {
                    return Err("simulation receipt must not carry hardware attestation");
                }
            }
            QuantumBackendMode::Hardware => {
                if matches!(self.hardware_attestation_root, None | Some([0; 32])) {
                    return Err("hardware receipt requires nonzero attestation root");
                }
            }
        }
        Ok(())
    }

    pub fn root(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(b"SYNERGY/PQ-RADIO/TELEPORTATION-RECEIPT/V1\0");
        h.update([self.mode.code()]);
        h.update(self.bell_pair_id);
        h.update([self.alice_measurement_q0, self.alice_measurement_q1]);
        h.update(self.source_state_commitment);
        h.update(self.destination_state_commitment);
        h.update(self.fidelity_ppb.to_be_bytes());
        h.update(self.hardware_attestation_root.unwrap_or([0; 32]));
        Some(h.finalize().into())
    }

    pub fn may_strengthen_physical_security_claim(&self) -> bool {
        self.mode == QuantumBackendMode::Hardware
            && self.hardware_attestation_root.is_some()
            && self.fidelity_ppb >= MIN_HARDWARE_FIDELITY_PPB
            && self.validate().is_ok()
    }
}

pub trait QuantumTeleportationBackend {
    fn mode(&self) -> QuantumBackendMode;
    fn teleport(&mut self, source: &QubitState) -> Result<TeleportationReceipt, &'static str>;
}


/// Raw result produced by a physical QPU / quantum-network driver.
///
/// The radio protocol does not decide whether an experiment is physically valid.
/// A hardware integration must provide a nonzero attestation root committing to
/// device identity, calibration, experiment metadata and raw measurement evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareTeleportationMeasurement {
    pub bell_pair_id: [u8; 32],
    pub alice_measurement_q0: u8,
    pub alice_measurement_q1: u8,
    pub source_state_commitment: [u8; 32],
    pub destination_state_commitment: [u8; 32],
    pub fidelity_ppb: u64,
    pub hardware_attestation_root: [u8; 32],
}

pub trait HardwareQuantumDriver {
    fn teleport_physical(
        &mut self,
        source: &QubitState,
    ) -> Result<HardwareTeleportationMeasurement, &'static str>;
}

pub struct AttestedHardwareTeleportationBackend<D> {
    driver: D,
}

impl<D> AttestedHardwareTeleportationBackend<D> {
    pub fn new(driver: D) -> Self {
        Self { driver }
    }

    pub fn into_inner(self) -> D {
        self.driver
    }
}

impl<D: HardwareQuantumDriver> QuantumTeleportationBackend
    for AttestedHardwareTeleportationBackend<D>
{
    fn mode(&self) -> QuantumBackendMode {
        QuantumBackendMode::Hardware
    }

    fn teleport(&mut self, source: &QubitState) -> Result<TeleportationReceipt, &'static str> {
        let measurement = self.driver.teleport_physical(source)?;
        if measurement.source_state_commitment != source.commitment() {
            return Err("hardware result not bound to requested source state");
        }
        let receipt = TeleportationReceipt {
            mode: QuantumBackendMode::Hardware,
            bell_pair_id: measurement.bell_pair_id,
            alice_measurement_q0: measurement.alice_measurement_q0,
            alice_measurement_q1: measurement.alice_measurement_q1,
            source_state_commitment: measurement.source_state_commitment,
            destination_state_commitment: measurement.destination_state_commitment,
            fidelity_ppb: measurement.fidelity_ppb,
            hardware_attestation_root: Some(measurement.hardware_attestation_root),
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

#[derive(Debug, Default)]
pub struct SimulatedTeleportationBackend;

impl SimulatedTeleportationBackend {
    pub fn teleport_with_measurements(
        source: &QubitState,
        measurement_q0: u8,
        measurement_q1: u8,
        bell_pair_id: [u8; 32],
    ) -> Result<(QubitState, TeleportationReceipt), &'static str> {
        if measurement_q0 > 1 || measurement_q1 > 1 {
            return Err("measurement outcomes must be bits");
        }
        if bell_pair_id == [0; 32] {
            return Err("Bell-pair id required");
        }

        let mut bob = match (measurement_q0, measurement_q1) {
            (0, 0) => *source,
            (0, 1) => QubitState {
                alpha: source.beta,
                beta: source.alpha,
            },
            (1, 0) => QubitState {
                alpha: source.alpha,
                beta: -source.beta,
            },
            (1, 1) => QubitState {
                alpha: -source.beta,
                beta: source.alpha,
            },
            _ => unreachable!(),
        };

        if measurement_q1 == 1 {
            bob = QubitState {
                alpha: bob.beta,
                beta: bob.alpha,
            };
        }
        if measurement_q0 == 1 {
            bob = QubitState {
                alpha: bob.alpha,
                beta: -bob.beta,
            };
        }

        let fidelity = source.fidelity(&bob);
        let fidelity_ppb = (fidelity * 1_000_000_000.0).round() as u64;
        let receipt = TeleportationReceipt {
            mode: QuantumBackendMode::Simulation,
            bell_pair_id,
            alice_measurement_q0: measurement_q0,
            alice_measurement_q1: measurement_q1,
            source_state_commitment: source.commitment(),
            destination_state_commitment: bob.commitment(),
            fidelity_ppb,
            hardware_attestation_root: None,
        };
        receipt.validate()?;
        Ok((bob, receipt))
    }
}

impl QuantumTeleportationBackend for SimulatedTeleportationBackend {
    fn mode(&self) -> QuantumBackendMode {
        QuantumBackendMode::Simulation
    }

    fn teleport(&mut self, source: &QubitState) -> Result<TeleportationReceipt, &'static str> {
        let mut rng = rand::rngs::OsRng;
        let bits = (rng.next_u32() & 0b11) as u8;
        let measurement_q0 = (bits >> 1) & 1;
        let measurement_q1 = bits & 1;

        let mut bell_pair_id = [0u8; 32];
        rng.try_fill_bytes(&mut bell_pair_id)
            .map_err(|_| "OS RNG failure")?;
        if bell_pair_id == [0; 32] {
            return Err("OS RNG returned zero Bell-pair id");
        }

        let (_, receipt) = Self::teleport_with_measurements(
            source,
            measurement_q0,
            measurement_q1,
            bell_pair_id,
        )?;
        Ok(receipt)
    }
}
