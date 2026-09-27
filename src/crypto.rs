use fips205::traits::{SerDes, Signer};
use ml_dsa::{Generate, Keypair, MlDsa87, SignatureEncoding, SigningKey};
use ml_kem::{
    ml_kem_1024::{
        Ciphertext as MlKem1024Ciphertext, DecapsulationKey as MlKem1024DecapsulationKey,
        EncapsulationKey as MlKem1024EncapsulationKey,
    },
    Decapsulate, Generate as KemGenerate, Key, KeyExport, B32,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const ML_KEM_1024_PUBLIC_KEY_BYTES: usize = 1568;
pub const ML_KEM_1024_CIPHERTEXT_BYTES: usize = 1568;
pub const ML_KEM_SHARED_SECRET_BYTES: usize = 32;
pub const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2592;
pub const ML_DSA_87_SIGNATURE_BYTES: usize = 4627;
pub const SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES: usize = 64;
pub const SLH_DSA_SHAKE_256S_SIGNATURE_BYTES: usize = 29792;

pub const HANDSHAKE_SIGNATURE_CONTEXT: &[u8] = b"SYNERGY/PQ-RADIO/HANDSHAKE/V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    pub node_id: [u8; 32],
    pub ml_dsa_public_key: Vec<u8>,
    pub slh_dsa_public_key: Vec<u8>,
}

impl PublicIdentity {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.node_id == [0; 32] {
            return Err("node id required");
        }
        if self.ml_dsa_public_key.len() != ML_DSA_87_PUBLIC_KEY_BYTES {
            return Err("ML-DSA-87 public-key length mismatch");
        }
        if self.slh_dsa_public_key.len() != SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES {
            return Err("SLH-DSA-SHAKE-256s public-key length mismatch");
        }
        if derive_node_id(&self.ml_dsa_public_key, &self.slh_dsa_public_key) != self.node_id {
            return Err("node id does not match PQ identity");
        }
        Ok(())
    }
}

pub struct PqIdentity {
    public: PublicIdentity,
    ml_dsa_secret: SigningKey<MlDsa87>,
    slh_dsa_secret: fips205::slh_dsa_shake_256s::PrivateKey,
}

impl PqIdentity {
    pub fn generate() -> Result<Self, &'static str> {
        let ml_dsa_secret = SigningKey::<MlDsa87>::try_generate()
            .map_err(|_| "ML-DSA-87 key generation failed")?;
        let ml_dsa_public_key = ml_dsa_secret.verifying_key().encode().to_vec();

        let (slh_public, slh_dsa_secret) =
            fips205::slh_dsa_shake_256s::try_keygen().map_err(|_| "SLH-DSA key generation failed")?;
        let slh_dsa_public_key = slh_public.into_bytes().to_vec();

        let node_id = derive_node_id(&ml_dsa_public_key, &slh_dsa_public_key);
        let public = PublicIdentity {
            node_id,
            ml_dsa_public_key,
            slh_dsa_public_key,
        };
        public.validate()?;

        Ok(Self {
            public,
            ml_dsa_secret,
            slh_dsa_secret,
        })
    }

    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }

    pub fn sign_handshake(&self, transcript_root: &[u8; 32]) -> Result<DualPqSignature, &'static str> {
        let ml_dsa_signature = self
            .ml_dsa_secret
            .expanded_key()
            .sign_deterministic(transcript_root, HANDSHAKE_SIGNATURE_CONTEXT)
            .map_err(|_| "ML-DSA signing failed")?
            .to_vec();

        let slh_dsa_signature = self
            .slh_dsa_secret
            .try_sign(transcript_root, HANDSHAKE_SIGNATURE_CONTEXT, true)
            .map_err(|_| "SLH-DSA signing failed")?
            .to_vec();

        let signature = DualPqSignature {
            ml_dsa_signature,
            slh_dsa_signature,
        };
        signature.validate()?;
        Ok(signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DualPqSignature {
    pub ml_dsa_signature: Vec<u8>,
    pub slh_dsa_signature: Vec<u8>,
}

impl DualPqSignature {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.ml_dsa_signature.len() != ML_DSA_87_SIGNATURE_BYTES {
            return Err("ML-DSA-87 signature length mismatch");
        }
        if self.slh_dsa_signature.len() != SLH_DSA_SHAKE_256S_SIGNATURE_BYTES {
            return Err("SLH-DSA-SHAKE-256s signature length mismatch");
        }
        Ok(())
    }
}

pub fn verify_dual_signature(
    identity: &PublicIdentity,
    transcript_root: &[u8; 32],
    signature: &DualPqSignature,
) -> bool {
    if identity.validate().is_err() || signature.validate().is_err() {
        return false;
    }

    verify_ml_dsa(
        &identity.ml_dsa_public_key,
        transcript_root,
        HANDSHAKE_SIGNATURE_CONTEXT,
        &signature.ml_dsa_signature,
    ) && verify_slh_dsa(
        &identity.slh_dsa_public_key,
        transcript_root,
        HANDSHAKE_SIGNATURE_CONTEXT,
        &signature.slh_dsa_signature,
    )
}

fn verify_ml_dsa(public_key: &[u8], message: &[u8], context: &[u8], signature: &[u8]) -> bool {
    use ml_dsa::{Signature, VerifyingKey};

    if context.len() > 255
        || public_key.len() != ML_DSA_87_PUBLIC_KEY_BYTES
        || signature.len() != ML_DSA_87_SIGNATURE_BYTES
    {
        return false;
    }

    let encoded_key = match ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(public_key) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let verifying_key = VerifyingKey::<MlDsa87>::decode(&encoded_key);
    let signature = match Signature::<MlDsa87>::try_from(signature) {
        Ok(value) => value,
        Err(_) => return false,
    };
    verifying_key.verify_with_context(message, context, &signature)
}

fn verify_slh_dsa(public_key: &[u8], message: &[u8], context: &[u8], signature: &[u8]) -> bool {
    use slh_dsa::{Shake256s, Signature, VerifyingKey};

    if context.len() > 255
        || public_key.len() != SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES
        || signature.len() != SLH_DSA_SHAKE_256S_SIGNATURE_BYTES
    {
        return false;
    }

    let verifying_key = match VerifyingKey::<Shake256s>::try_from(public_key) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let signature = match Signature::<Shake256s>::try_from(signature) {
        Ok(value) => value,
        Err(_) => return false,
    };
    verifying_key
        .try_verify_with_context(message, context, &signature)
        .is_ok()
}

fn derive_node_id(ml_dsa_public_key: &[u8], slh_dsa_public_key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SYNERGY/PQ-RADIO/NODE-ID/V1\0");
    h.update((ml_dsa_public_key.len() as u64).to_be_bytes());
    h.update(ml_dsa_public_key);
    h.update((slh_dsa_public_key.len() as u64).to_be_bytes());
    h.update(slh_dsa_public_key);
    h.finalize().into()
}

pub struct KemKeypair {
    secret: MlKem1024DecapsulationKey,
    public_key: Vec<u8>,
}

impl KemKeypair {
    pub fn generate() -> Result<Self, &'static str> {
        let secret = MlKem1024DecapsulationKey::try_generate()
            .map_err(|_| "ML-KEM-1024 key generation failed")?;
        let public_key = secret.encapsulation_key().clone().to_bytes().as_slice().to_vec();
        if public_key.len() != ML_KEM_1024_PUBLIC_KEY_BYTES {
            return Err("unexpected ML-KEM-1024 public-key length");
        }
        Ok(Self { secret, public_key })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SharedSecret, &'static str> {
        if ciphertext.len() != ML_KEM_1024_CIPHERTEXT_BYTES {
            return Err("ML-KEM-1024 ciphertext length mismatch");
        }
        let ciphertext =
            MlKem1024Ciphertext::try_from(ciphertext).map_err(|_| "invalid ML-KEM ciphertext")?;
        let mut shared = self.secret.decapsulate(&ciphertext);
        let wrapped = SharedSecret::from_slice(shared.as_ref())?;
        shared.zeroize();
        Ok(wrapped)
    }
}

pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, SharedSecret), &'static str> {
    if public_key.len() != ML_KEM_1024_PUBLIC_KEY_BYTES {
        return Err("ML-KEM-1024 public-key length mismatch");
    }

    let encoded = Key::<MlKem1024EncapsulationKey>::try_from(public_key)
        .map_err(|_| "invalid ML-KEM public-key encoding")?;
    let ek = MlKem1024EncapsulationKey::new(&encoded).map_err(|_| "invalid ML-KEM public key")?;

    let mut randomness_bytes = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut randomness_bytes)
        .map_err(|_| "OS RNG failure")?;
    let mut randomness =
        B32::try_from(randomness_bytes.as_slice()).map_err(|_| "ML-KEM randomness error")?;
    randomness_bytes.zeroize();

    let (ciphertext, mut shared) = ek.encapsulate_deterministic(&randomness);
    randomness.zeroize();

    let wrapped = SharedSecret::from_slice(shared.as_ref())?;
    shared.zeroize();

    Ok((ciphertext.as_slice().to_vec(), wrapped))
}

pub struct SharedSecret([u8; ML_KEM_SHARED_SECRET_BYTES]);

impl SharedSecret {
    fn from_slice(bytes: &[u8]) -> Result<Self, &'static str> {
        let value: [u8; ML_KEM_SHARED_SECRET_BYTES] =
            bytes.try_into().map_err(|_| "ML-KEM shared-secret length mismatch")?;
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8; ML_KEM_SHARED_SECRET_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
