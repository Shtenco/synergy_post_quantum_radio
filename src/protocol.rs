use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::crypto::{
    encapsulate, verify_dual_signature, DualPqSignature, KemKeypair, PqIdentity, PublicIdentity,
    SharedSecret, ML_KEM_1024_CIPHERTEXT_BYTES, ML_KEM_1024_PUBLIC_KEY_BYTES,
};
use crate::pi_pq::PiPqEvidence;
use crate::quantum::TeleportationReceipt;

pub const SESSION_KEY_BYTES: usize = 32;
pub const SESSION_ID_BYTES: usize = 32;
pub const MAX_FRAME_BYTES: usize = 1_048_576;
pub const MAX_SEQUENCE: u64 = u64::MAX - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioCapabilities {
    pub frequency_hz: u64,
    pub bandwidth_hz: u32,
    pub modem: String,
}

impl RadioCapabilities {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.frequency_hz == 0 || self.bandwidth_hz == 0 || self.modem.is_empty() {
            return Err("radio capabilities incomplete");
        }
        if self.modem.len() > 64 {
            return Err("modem name too long");
        }
        Ok(())
    }

    pub fn root(&self) -> Option<[u8;32]> {
        self.validate().ok()?;
        let mut h=Sha256::new();
        h.update(b"SYNERGY/PQ-RADIO/CAPABILITIES/V1\0");
        h.update(self.frequency_hz.to_be_bytes());
        h.update(self.bandwidth_hz.to_be_bytes());
        h.update((self.modem.len() as u64).to_be_bytes());
        h.update(self.modem.as_bytes());
        Some(h.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub session_id: [u8; SESSION_ID_BYTES],
    pub epoch: u64,
    pub identity: PublicIdentity,
    pub ephemeral_ml_kem_public_key: Vec<u8>,
    pub radio: RadioCapabilities,
    pub teleportation_root: Option<[u8;32]>,
    pub pi_pq_root: Option<[u8;32]>,
}

impl ClientHello {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.session_id == [0; SESSION_ID_BYTES] || self.epoch == 0 {
            return Err("session id and epoch required");
        }
        self.identity.validate()?;
        if self.ephemeral_ml_kem_public_key.len() != ML_KEM_1024_PUBLIC_KEY_BYTES {
            return Err("client ML-KEM public key length mismatch");
        }
        self.radio.validate()?;
        Ok(())
    }

    pub fn root(&self) -> Option<[u8;32]> {
        self.validate().ok()?;
        let mut h=Sha256::new();
        h.update(b"SYNERGY/PQ-RADIO/CLIENT-HELLO/V1\0");
        h.update(crate::PROTOCOL_VERSION.to_be_bytes());
        h.update(self.session_id);
        h.update(self.epoch.to_be_bytes());
        h.update(self.identity.node_id);
        h.update(self.radio.root()?);
        h.update((self.ephemeral_ml_kem_public_key.len() as u64).to_be_bytes());
        h.update(&self.ephemeral_ml_kem_public_key);
        h.update(self.teleportation_root.unwrap_or([0;32]));
        h.update(self.pi_pq_root.unwrap_or([0;32]));
        Some(h.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub client_hello_root: [u8;32],
    pub identity: PublicIdentity,
    pub responder_ephemeral_ml_kem_public_key: Vec<u8>,
    pub ml_kem_ciphertext_to_client: Vec<u8>,
    pub radio: RadioCapabilities,
    pub teleportation_root: Option<[u8;32]>,
    pub pi_pq_root: Option<[u8;32]>,
}

impl ServerHello {
    pub fn validate_against(&self, client: &ClientHello) -> Result<(), &'static str> {
        client.validate()?;
        if self.client_hello_root != client.root().ok_or("client hello root unavailable")? {
            return Err("server hello not bound to client hello");
        }
        self.identity.validate()?;
        if self.identity.node_id == client.identity.node_id {
            return Err("radio peers must be distinct");
        }
        if self.responder_ephemeral_ml_kem_public_key.len() != ML_KEM_1024_PUBLIC_KEY_BYTES {
            return Err("server ML-KEM public key length mismatch");
        }
        if self.ml_kem_ciphertext_to_client.len() != ML_KEM_1024_CIPHERTEXT_BYTES {
            return Err("ML-KEM ciphertext length mismatch");
        }
        self.radio.validate()?;
        Ok(())
    }

    pub fn transcript_root(&self, client: &ClientHello) -> Option<[u8;32]> {
        self.validate_against(client).ok()?;
        let mut h=Sha256::new();
        h.update(b"SYNERGY/PQ-RADIO/HANDSHAKE-TRANSCRIPT/V1\0");
        h.update(crate::PROTOCOL_VERSION.to_be_bytes());
        h.update(client.root()?);
        h.update(self.identity.node_id);
        h.update(self.radio.root()?);
        h.update((self.responder_ephemeral_ml_kem_public_key.len() as u64).to_be_bytes());
        h.update(&self.responder_ephemeral_ml_kem_public_key);
        h.update((self.ml_kem_ciphertext_to_client.len() as u64).to_be_bytes());
        h.update(&self.ml_kem_ciphertext_to_client);
        h.update(self.teleportation_root.unwrap_or([0;32]));
        h.update(self.pi_pq_root.unwrap_or([0;32]));
        Some(h.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedServerHello {
    pub hello: ServerHello,
    pub server_signature: DualPqSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientFinish {
    pub transcript_root: [u8;32],
    pub ml_kem_ciphertext_to_server: Vec<u8>,
    pub client_signature: DualPqSignature,
}

pub struct ClientHandshakeState {
    pub hello: ClientHello,
    kem: KemKeypair,
}

pub struct ServerHandshakeState {
    pub authenticated_hello: AuthenticatedServerHello,
    kem: KemKeypair,
    shared_with_client: SharedSecret,
}

pub fn start_client(
    identity: &PqIdentity,
    epoch: u64,
    radio: RadioCapabilities,
    teleportation: Option<&TeleportationReceipt>,
    pi_pq: Option<&PiPqEvidence>,
) -> Result<ClientHandshakeState, &'static str> {
    let kem=KemKeypair::generate()?;
    let mut session_id=[0u8;32];
    rand::rngs::OsRng.try_fill_bytes(&mut session_id).map_err(|_|"OS RNG failure")?;
    if session_id == [0;32] { return Err("zero session id"); }

    let hello=ClientHello {
        session_id,
        epoch,
        identity: identity.public().clone(),
        ephemeral_ml_kem_public_key: kem.public_key().to_vec(),
        radio,
        teleportation_root: teleportation.and_then(|x|x.root()),
        pi_pq_root: pi_pq.and_then(|x|x.evidence_root()),
    };
    hello.validate()?;
    Ok(ClientHandshakeState { hello, kem })
}

pub fn accept_server(
    identity: &PqIdentity,
    client: &ClientHello,
    radio: RadioCapabilities,
    teleportation: Option<&TeleportationReceipt>,
    pi_pq: Option<&PiPqEvidence>,
) -> Result<ServerHandshakeState, &'static str> {
    client.validate()?;
    let kem=KemKeypair::generate()?;
    let (ciphertext, shared_with_client)=encapsulate(&client.ephemeral_ml_kem_public_key)?;
    let hello=ServerHello {
        client_hello_root: client.root().ok_or("client hello root unavailable")?,
        identity: identity.public().clone(),
        responder_ephemeral_ml_kem_public_key: kem.public_key().to_vec(),
        ml_kem_ciphertext_to_client: ciphertext,
        radio,
        teleportation_root: teleportation.and_then(|x|x.root()),
        pi_pq_root: pi_pq.and_then(|x|x.evidence_root()),
    };
    let transcript_root=hello.transcript_root(client).ok_or("invalid transcript")?;
    let server_signature=identity.sign_handshake(&transcript_root)?;
    Ok(ServerHandshakeState {
        authenticated_hello: AuthenticatedServerHello { hello, server_signature },
        kem,
        shared_with_client,
    })
}

pub fn finish_client(
    identity: &PqIdentity,
    state: &ClientHandshakeState,
    server: &AuthenticatedServerHello,
) -> Result<(ClientFinish, RadioSession), &'static str> {
    let transcript_root=server.hello.transcript_root(&state.hello).ok_or("invalid server hello")?;
    if !verify_dual_signature(&server.hello.identity,&transcript_root,&server.server_signature) {
        return Err("server dual-PQ signature verification failed");
    }

    let server_shared=state.kem.decapsulate(&server.hello.ml_kem_ciphertext_to_client)?;
    let (client_to_server_ct, client_to_server_shared)=encapsulate(
        &server.hello.responder_ephemeral_ml_kem_public_key
    )?;

    let finish_root=client_finish_root(&transcript_root,&client_to_server_ct)?;
    let client_signature=identity.sign_handshake(&finish_root)?;

    let session=derive_session(
        &state.hello,
        &server.hello,
        &server_shared,
        &client_to_server_shared,
        &client_to_server_ct,
        SessionRole::Client,
    )?;

    Ok((
        ClientFinish {
            transcript_root: finish_root,
            ml_kem_ciphertext_to_server: client_to_server_ct,
            client_signature,
        },
        session,
    ))
}

pub fn finish_server(
    state: &ServerHandshakeState,
    client: &ClientHello,
    finish: &ClientFinish,
) -> Result<RadioSession, &'static str> {
    let transcript_root=state.authenticated_hello.hello.transcript_root(client)
        .ok_or("invalid transcript")?;
    let expected_finish_root=client_finish_root(
        &transcript_root,
        &finish.ml_kem_ciphertext_to_server,
    )?;
    if finish.transcript_root != expected_finish_root {
        return Err("client finish transcript mismatch");
    }
    if !verify_dual_signature(&client.identity,&finish.transcript_root,&finish.client_signature) {
        return Err("client dual-PQ signature verification failed");
    }

    let responder_shared=state
        .kem
        .decapsulate(&finish.ml_kem_ciphertext_to_server)?;
    derive_session(
        client,
        &state.authenticated_hello.hello,
        &state.shared_with_client,
        &responder_shared,
        &finish.ml_kem_ciphertext_to_server,
        SessionRole::Server,
    )
}

fn client_finish_root(transcript_root:&[u8;32], ciphertext:&[u8]) -> Result<[u8;32], &'static str> {
    if ciphertext.len()!=ML_KEM_1024_CIPHERTEXT_BYTES { return Err("client finish KEM ciphertext length mismatch"); }
    let mut h=Sha256::new();
    h.update(b"SYNERGY/PQ-RADIO/CLIENT-FINISH/V1\0");
    h.update(transcript_root);
    h.update((ciphertext.len() as u64).to_be_bytes());
    h.update(ciphertext);
    Ok(h.finalize().into())
}

#[derive(Clone, Copy)]
enum SessionRole {
    Client,
    Server,
}

fn derive_session(
    client:&ClientHello,
    server:&ServerHello,
    secret_a:&SharedSecret,
    secret_b:&SharedSecret,
    client_to_server_ciphertext:&[u8],
    role: SessionRole,
)->Result<RadioSession,&'static str>{
    let transcript=server.transcript_root(client).ok_or("invalid transcript")?;
    let finish=client_finish_root(&transcript,client_to_server_ciphertext)?;

    let mut ikm=[0u8;64];
    ikm[..32].copy_from_slice(secret_a.as_bytes());
    ikm[32..].copy_from_slice(secret_b.as_bytes());

    let hk=Hkdf::<Sha256>::new(Some(&finish),&ikm);
    let mut client_to_server_key=[0u8;SESSION_KEY_BYTES];
    let mut server_to_client_key=[0u8;SESSION_KEY_BYTES];
    hk.expand(b"SYNERGY/PQ-RADIO/CLIENT-TO-SERVER/V1",&mut client_to_server_key)
        .map_err(|_|"HKDF client-to-server expand failed")?;
    hk.expand(b"SYNERGY/PQ-RADIO/SERVER-TO-CLIENT/V1",&mut server_to_client_key)
        .map_err(|_|"HKDF server-to-client expand failed")?;
    ikm.zeroize();

    let (tx_key,rx_key,tx_direction,rx_direction)=match role {
        SessionRole::Client => (client_to_server_key,server_to_client_key,0x01,0x02),
        SessionRole::Server => (server_to_client_key,client_to_server_key,0x02,0x01),
    };

    Ok(RadioSession {
        session_id: client.session_id,
        peer_a: client.identity.node_id,
        peer_b: server.identity.node_id,
        transcript_root: finish,
        tx_key,
        rx_key,
        tx_direction,
        rx_direction,
        send_sequence:0,
        receive_sequence:0,
    })
}

pub struct RadioSession {
    pub session_id:[u8;32],
    pub peer_a:[u8;32],
    pub peer_b:[u8;32],
    pub transcript_root:[u8;32],
    tx_key:[u8;SESSION_KEY_BYTES],
    rx_key:[u8;SESSION_KEY_BYTES],
    tx_direction:u8,
    rx_direction:u8,
    send_sequence:u64,
    receive_sequence:u64,
}

impl Drop for RadioSession {
    fn drop(&mut self) {
        self.tx_key.zeroize();
        self.rx_key.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedRadioFrame {
    pub session_id:[u8;32],
    pub sequence:u64,
    pub aad_root:[u8;32],
    pub ciphertext:Vec<u8>,
}

impl RadioSession {
    pub fn encrypt(&mut self, aad_root:[u8;32], plaintext:&[u8]) -> Result<EncryptedRadioFrame,&'static str> {
        if plaintext.len()>MAX_FRAME_BYTES { return Err("radio frame too large"); }
        if self.send_sequence>=MAX_SEQUENCE { return Err("send sequence exhausted"); }
        if aad_root==[0;32] { return Err("AAD root required"); }

        let sequence=self.send_sequence;
        let nonce=nonce_for(self.session_id,sequence,self.tx_direction);
        let aad=frame_aad(self.session_id,sequence,aad_root);
        let cipher=ChaCha20Poly1305::new((&self.tx_key).into());
        let ciphertext=cipher.encrypt(Nonce::from_slice(&nonce),Payload{msg:plaintext,aad:&aad})
            .map_err(|_|"radio encryption failed")?;
        self.send_sequence+=1;
        Ok(EncryptedRadioFrame{session_id:self.session_id,sequence,aad_root,ciphertext})
    }

    pub fn decrypt(&mut self, frame:&EncryptedRadioFrame) -> Result<Vec<u8>,&'static str> {
        if frame.session_id!=self.session_id { return Err("session mismatch"); }
        if frame.sequence!=self.receive_sequence { return Err("replay or out-of-order frame"); }
        if frame.aad_root==[0;32] { return Err("AAD root required"); }
        let nonce=nonce_for(self.session_id,frame.sequence,self.rx_direction);
        let aad=frame_aad(self.session_id,frame.sequence,frame.aad_root);
        let cipher=ChaCha20Poly1305::new((&self.rx_key).into());
        let plaintext=cipher.decrypt(Nonce::from_slice(&nonce),Payload{msg:&frame.ciphertext,aad:&aad})
            .map_err(|_|"radio authentication failed")?;
        self.receive_sequence+=1;
        Ok(plaintext)
    }
}

fn nonce_for(session_id:[u8;32],sequence:u64,direction:u8)->[u8;12]{
    let mut h=Sha256::new();
    h.update(b"SYNERGY/PQ-RADIO/NONCE/V1\0");
    h.update(session_id);
    h.update([direction]);
    h.update(sequence.to_be_bytes());
    let digest:[u8;32]=h.finalize().into();
    digest[..12].try_into().expect("slice length")
}

fn frame_aad(session_id:[u8;32],sequence:u64,aad_root:[u8;32])->Vec<u8>{
    let mut out=Vec::with_capacity(72);
    out.extend_from_slice(b"SYNERGY/PQ-RADIO/FRAME/V1\0");
    out.extend_from_slice(&session_id);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&aad_root);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quantum::{QubitState, QuantumTeleportationBackend, SimulatedTeleportationBackend};

    fn radio()->RadioCapabilities{
        RadioCapabilities{
            frequency_hz:915_000_000,
            bandwidth_hz:125_000,
            modem:"SIM-LORA".into(),
        }
    }

    #[test]
    fn full_handshake_and_bidirectional_encrypted_frames_roundtrip() {
        let alice=PqIdentity::generate().expect("alice");
        let bob=PqIdentity::generate().expect("bob");
        let mut q=SimulatedTeleportationBackend::default();
        let tq=q.teleport(&QubitState::plus()).expect("teleport");

        let client=start_client(&alice,1,radio(),Some(&tq),None).expect("client");
        let server=accept_server(&bob,&client.hello,radio(),Some(&tq),None).expect("server");

        let (finish,mut client_session)=finish_client(
            &alice,
            &client,
            &server.authenticated_hello,
        ).expect("client finish");
        let mut server_session=finish_server(&server,&client.hello,&finish).expect("server finish");

        assert_eq!(client_session.transcript_root,server_session.transcript_root);

        let aad=[7u8;32];
        let frame=client_session.encrypt(aad,b"radio payload").unwrap();
        let decoded=server_session.decrypt(&frame).unwrap();
        assert_eq!(decoded,b"radio payload");
        assert!(server_session.decrypt(&frame).is_err());

        let reply=server_session.encrypt([8u8;32],b"ack").unwrap();
        let decoded_reply=client_session.decrypt(&reply).unwrap();
        assert_eq!(decoded_reply,b"ack");
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let alice=PqIdentity::generate().expect("alice");
        let bob=PqIdentity::generate().expect("bob");
        let client=start_client(&alice,1,radio(),None,None).expect("client");
        let server=accept_server(&bob,&client.hello,radio(),None,None).expect("server");
        let (finish,mut client_session)=finish_client(
            &alice,&client,&server.authenticated_hello
        ).expect("client finish");
        let mut server_session=finish_server(&server,&client.hello,&finish).expect("server finish");

        let mut frame=client_session.encrypt([3u8;32],b"secret").unwrap();
        frame.ciphertext[0]^=0x01;
        assert!(server_session.decrypt(&frame).is_err());
    }
}
