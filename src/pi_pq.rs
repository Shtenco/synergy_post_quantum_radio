use sha2::{Digest, Sha256};

pub const PI_PQ_EVIDENCE_DOMAIN: &[u8] = b"SYNERGY/PI-PQ-EVIDENCE/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiPqEvidence {
    pub algorithm_source_hash: [u8; 32],
    pub specification_hash: [u8; 32],
    pub test_vector_root: [u8; 32],
    pub input_commitment: [u8; 32],
    pub output_commitment: [u8; 32],
    pub version: u32,
}

impl PiPqEvidence {
    pub fn validate_non_authoritative(&self) -> Result<(), &'static str> {
        if self.algorithm_source_hash == [0; 32]
            || self.specification_hash == [0; 32]
            || self.test_vector_root == [0; 32]
            || self.input_commitment == [0; 32]
            || self.output_commitment == [0; 32]
            || self.version == 0
        {
            return Err("PI-PQ evidence fields required");
        }
        Ok(())
    }

    pub fn evidence_root(&self) -> Option<[u8; 32]> {
        self.validate_non_authoritative().ok()?;
        let mut h = Sha256::new();
        h.update(PI_PQ_EVIDENCE_DOMAIN);
        h.update(crate::PROTOCOL_VERSION.to_be_bytes());
        h.update(self.algorithm_source_hash);
        h.update(self.specification_hash);
        h.update(self.test_vector_root);
        h.update(self.input_commitment);
        h.update(self.output_commitment);
        h.update(self.version.to_be_bytes());
        Some(h.finalize().into())
    }

    pub const fn may_authorize_radio_session(&self) -> bool { false }
    pub const fn may_replace_standard_pqc(&self) -> bool { false }
}
