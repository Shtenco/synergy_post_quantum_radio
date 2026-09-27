use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::crypto::{
    DualPqSignature, PublicIdentity, ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES,
    ML_KEM_1024_CIPHERTEXT_BYTES, ML_KEM_1024_PUBLIC_KEY_BYTES,
    SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES, SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
};
use crate::protocol::{
    AuthenticatedServerHello, ClientFinish, ClientHello, EncryptedRadioFrame, RadioCapabilities,
    ServerHello, MAX_FRAME_BYTES,
};
use crate::radio::RadioLink;

const WIRE_MAGIC: &[u8; 4] = b"SPQR";
const FRAGMENT_MAGIC: &[u8; 4] = b"SPQF";
const WIRE_VERSION: u16 = 1;
const FRAGMENT_VERSION: u8 = 1;
const FRAGMENT_HEADER_BYTES: usize = 61;
pub const MAX_WIRE_MESSAGE_BYTES: usize = 262_144;
pub const MAX_WIRE_FRAGMENTS: u32 = 8_192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireMessage {
    ClientHello(ClientHello),
    ServerHello(AuthenticatedServerHello),
    ClientFinish(ClientFinish),
    EncryptedFrame(EncryptedRadioFrame),
}

impl WireMessage {
    fn type_code(&self) -> u8 {
        match self {
            Self::ClientHello(_) => 1,
            Self::ServerHello(_) => 2,
            Self::ClientFinish(_) => 3,
            Self::EncryptedFrame(_) => 4,
        }
    }
}

pub fn encode_message(message: &WireMessage) -> Result<Vec<u8>, &'static str> {
    let mut body = Vec::new();
    match message {
        WireMessage::ClientHello(v) => encode_client_hello(&mut body, v)?,
        WireMessage::ServerHello(v) => encode_authenticated_server_hello(&mut body, v)?,
        WireMessage::ClientFinish(v) => encode_client_finish(&mut body, v)?,
        WireMessage::EncryptedFrame(v) => encode_encrypted_frame(&mut body, v)?,
    }
    if body.len() > MAX_WIRE_MESSAGE_BYTES {
        return Err("wire message too large");
    }
    let mut out = Vec::with_capacity(11 + body.len());
    out.extend_from_slice(WIRE_MAGIC);
    out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    out.push(message.type_code());
    put_u32(&mut out, body.len())?;
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode_message(bytes: &[u8]) -> Result<WireMessage, &'static str> {
    if bytes.len() < 11 || &bytes[..4] != WIRE_MAGIC {
        return Err("invalid wire magic");
    }
    let mut c = Cursor::new(bytes);
    c.take_exact(4)?;
    if c.u16()? != WIRE_VERSION {
        return Err("unsupported wire version");
    }
    let kind = c.u8()?;
    let body_len = c.u32()? as usize;
    if body_len > MAX_WIRE_MESSAGE_BYTES || c.remaining() != body_len {
        return Err("wire body length mismatch");
    }
    let body = c.take_exact(body_len)?;
    let mut b = Cursor::new(body);
    let message = match kind {
        1 => WireMessage::ClientHello(decode_client_hello(&mut b)?),
        2 => WireMessage::ServerHello(decode_authenticated_server_hello(&mut b)?),
        3 => WireMessage::ClientFinish(decode_client_finish(&mut b)?),
        4 => WireMessage::EncryptedFrame(decode_encrypted_frame(&mut b)?),
        _ => return Err("unknown wire message type"),
    };
    if b.remaining() != 0 {
        return Err("trailing wire bytes");
    }
    Ok(message)
}

pub fn send_wire_message<L: RadioLink>(
    link: &mut L,
    message: &WireMessage,
) -> Result<(), &'static str> {
    let encoded = encode_message(message)?;
    let mtu = link.mtu();
    if mtu <= FRAGMENT_HEADER_BYTES {
        return Err("radio MTU too small for fragment header");
    }
    let payload_per_fragment = mtu - FRAGMENT_HEADER_BYTES;
    let total_usize = encoded.len().div_ceil(payload_per_fragment);
    let total = u32::try_from(total_usize).map_err(|_| "too many radio fragments")?;
    if total == 0 || total > MAX_WIRE_FRAGMENTS {
        return Err("wire message requires too many fragments");
    }

    let mut message_id = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut message_id)
        .map_err(|_| "OS RNG failure")?;
    if message_id == [0; 16] {
        return Err("zero fragment message id");
    }

    let root: [u8; 32] = Sha256::digest(&encoded).into();
    for (index, chunk) in encoded.chunks(payload_per_fragment).enumerate() {
        let index = u32::try_from(index).map_err(|_| "fragment index overflow")?;
        let mut frame = Vec::with_capacity(FRAGMENT_HEADER_BYTES + chunk.len());
        frame.extend_from_slice(FRAGMENT_MAGIC);
        frame.push(FRAGMENT_VERSION);
        frame.extend_from_slice(&message_id);
        frame.extend_from_slice(&index.to_be_bytes());
        frame.extend_from_slice(&total.to_be_bytes());
        frame.extend_from_slice(&root);
        frame.extend_from_slice(chunk);
        link.send(&frame)?;
    }
    Ok(())
}

pub fn receive_wire_message<L: RadioLink>(link: &mut L) -> Result<WireMessage, &'static str> {
    let first = link.receive()?;
    let first_fragment = parse_fragment(&first)?;
    let total = first_fragment.total;
    if total == 0 || total > MAX_WIRE_FRAGMENTS {
        return Err("invalid fragment count");
    }
    let max_payload = link
        .mtu()
        .checked_sub(FRAGMENT_HEADER_BYTES)
        .ok_or("radio MTU too small for fragment header")?;
    let max_reassembled = (total as usize)
        .checked_mul(max_payload)
        .ok_or("fragment allocation overflow")?;
    if max_reassembled > MAX_WIRE_MESSAGE_BYTES + max_payload {
        return Err("fragment set exceeds wire message limit");
    }

    let mut chunks: Vec<Option<Vec<u8>>> = vec![None; total as usize];
    let message_id = first_fragment.message_id;
    let root = first_fragment.root;
    store_fragment(&mut chunks, first_fragment)?;

    while chunks.iter().any(Option::is_none) {
        let raw = link.receive()?;
        let fragment = parse_fragment(&raw)?;
        if fragment.message_id != message_id || fragment.root != root || fragment.total != total {
            return Err("interleaved or conflicting fragment set");
        }
        store_fragment(&mut chunks, fragment)?;
    }

    let mut encoded = Vec::new();
    for chunk in chunks {
        encoded.extend_from_slice(&chunk.ok_or("missing fragment")?);
        if encoded.len() > MAX_WIRE_MESSAGE_BYTES {
            return Err("reassembled wire message too large");
        }
    }
    let actual: [u8; 32] = Sha256::digest(&encoded).into();
    if actual != root {
        return Err("wire fragment root mismatch");
    }
    decode_message(&encoded)
}

struct Fragment<'a> {
    message_id: [u8; 16],
    index: u32,
    total: u32,
    root: [u8; 32],
    payload: &'a [u8],
}

fn parse_fragment(raw: &[u8]) -> Result<Fragment<'_>, &'static str> {
    if raw.len() < FRAGMENT_HEADER_BYTES || &raw[..4] != FRAGMENT_MAGIC {
        return Err("invalid radio fragment");
    }
    if raw[4] != FRAGMENT_VERSION {
        return Err("unsupported fragment version");
    }
    let message_id: [u8; 16] = raw[5..21].try_into().map_err(|_| "fragment id")?;
    let index = u32::from_be_bytes(raw[21..25].try_into().map_err(|_| "fragment index")?);
    let total = u32::from_be_bytes(raw[25..29].try_into().map_err(|_| "fragment total")?);
    let root: [u8; 32] = raw[29..61].try_into().map_err(|_| "fragment root")?;
    if total == 0 || index >= total {
        return Err("fragment index outside set");
    }
    Ok(Fragment {
        message_id,
        index,
        total,
        root,
        payload: &raw[61..],
    })
}

fn store_fragment(
    chunks: &mut [Option<Vec<u8>>],
    fragment: Fragment<'_>,
) -> Result<(), &'static str> {
    let slot = chunks
        .get_mut(fragment.index as usize)
        .ok_or("fragment index overflow")?;
    match slot {
        Some(existing) if existing.as_slice() != fragment.payload => {
            Err("conflicting duplicate fragment")
        }
        Some(_) => Ok(()),
        None => {
            *slot = Some(fragment.payload.to_vec());
            Ok(())
        }
    }
}

fn encode_client_hello(out: &mut Vec<u8>, v: &ClientHello) -> Result<(), &'static str> {
    v.validate()?;
    out.extend_from_slice(&v.session_id);
    out.extend_from_slice(&v.epoch.to_be_bytes());
    encode_identity(out, &v.identity)?;
    put_bytes(out, &v.ephemeral_ml_kem_public_key)?;
    encode_radio(out, &v.radio)?;
    put_optional_root(out, v.teleportation_root);
    put_optional_root(out, v.pi_pq_root);
    Ok(())
}

fn decode_client_hello(c: &mut Cursor<'_>) -> Result<ClientHello, &'static str> {
    let v = ClientHello {
        session_id: c.array_32()?,
        epoch: c.u64()?,
        identity: decode_identity(c)?,
        ephemeral_ml_kem_public_key: c.bytes(ML_KEM_1024_PUBLIC_KEY_BYTES)?,
        radio: decode_radio(c)?,
        teleportation_root: c.optional_root()?,
        pi_pq_root: c.optional_root()?,
    };
    v.validate()?;
    Ok(v)
}

fn encode_authenticated_server_hello(
    out: &mut Vec<u8>,
    v: &AuthenticatedServerHello,
) -> Result<(), &'static str> {
    v.server_signature.validate()?;
    out.extend_from_slice(&v.hello.client_hello_root);
    encode_identity(out, &v.hello.identity)?;
    put_bytes(out, &v.hello.responder_ephemeral_ml_kem_public_key)?;
    put_bytes(out, &v.hello.ml_kem_ciphertext_to_client)?;
    encode_radio(out, &v.hello.radio)?;
    put_optional_root(out, v.hello.teleportation_root);
    put_optional_root(out, v.hello.pi_pq_root);
    encode_signature(out, &v.server_signature)?;
    Ok(())
}

fn decode_authenticated_server_hello(
    c: &mut Cursor<'_>,
) -> Result<AuthenticatedServerHello, &'static str> {
    let hello = ServerHello {
        client_hello_root: c.array_32()?,
        identity: decode_identity(c)?,
        responder_ephemeral_ml_kem_public_key: c.bytes(ML_KEM_1024_PUBLIC_KEY_BYTES)?,
        ml_kem_ciphertext_to_client: c.bytes(ML_KEM_1024_CIPHERTEXT_BYTES)?,
        radio: decode_radio(c)?,
        teleportation_root: c.optional_root()?,
        pi_pq_root: c.optional_root()?,
    };
    hello.identity.validate()?;
    hello.radio.validate()?;
    let server_signature = decode_signature(c)?;
    Ok(AuthenticatedServerHello {
        hello,
        server_signature,
    })
}

fn encode_client_finish(out: &mut Vec<u8>, v: &ClientFinish) -> Result<(), &'static str> {
    if v.ml_kem_ciphertext_to_server.len() != ML_KEM_1024_CIPHERTEXT_BYTES {
        return Err("client finish KEM ciphertext length mismatch");
    }
    v.client_signature.validate()?;
    out.extend_from_slice(&v.transcript_root);
    put_bytes(out, &v.ml_kem_ciphertext_to_server)?;
    encode_signature(out, &v.client_signature)?;
    Ok(())
}

fn decode_client_finish(c: &mut Cursor<'_>) -> Result<ClientFinish, &'static str> {
    let v = ClientFinish {
        transcript_root: c.array_32()?,
        ml_kem_ciphertext_to_server: c.bytes(ML_KEM_1024_CIPHERTEXT_BYTES)?,
        client_signature: decode_signature(c)?,
    };
    v.client_signature.validate()?;
    Ok(v)
}

fn encode_encrypted_frame(out: &mut Vec<u8>, v: &EncryptedRadioFrame) -> Result<(), &'static str> {
    if v.session_id == [0; 32] || v.aad_root == [0; 32] {
        return Err("invalid encrypted frame metadata");
    }
    if v.ciphertext.len() > MAX_FRAME_BYTES + 16 {
        return Err("encrypted frame too large");
    }
    out.extend_from_slice(&v.session_id);
    out.extend_from_slice(&v.sequence.to_be_bytes());
    out.extend_from_slice(&v.aad_root);
    put_bytes(out, &v.ciphertext)?;
    Ok(())
}

fn decode_encrypted_frame(c: &mut Cursor<'_>) -> Result<EncryptedRadioFrame, &'static str> {
    let v = EncryptedRadioFrame {
        session_id: c.array_32()?,
        sequence: c.u64()?,
        aad_root: c.array_32()?,
        ciphertext: c.bytes(MAX_FRAME_BYTES + 16)?,
    };
    if v.session_id == [0; 32] || v.aad_root == [0; 32] {
        return Err("invalid encrypted frame metadata");
    }
    Ok(v)
}

fn encode_identity(out: &mut Vec<u8>, v: &PublicIdentity) -> Result<(), &'static str> {
    v.validate()?;
    out.extend_from_slice(&v.node_id);
    put_bytes(out, &v.ml_dsa_public_key)?;
    put_bytes(out, &v.slh_dsa_public_key)?;
    Ok(())
}

fn decode_identity(c: &mut Cursor<'_>) -> Result<PublicIdentity, &'static str> {
    let v = PublicIdentity {
        node_id: c.array_32()?,
        ml_dsa_public_key: c.bytes(ML_DSA_87_PUBLIC_KEY_BYTES)?,
        slh_dsa_public_key: c.bytes(SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES)?,
    };
    v.validate()?;
    Ok(v)
}

fn encode_signature(out: &mut Vec<u8>, v: &DualPqSignature) -> Result<(), &'static str> {
    v.validate()?;
    put_bytes(out, &v.ml_dsa_signature)?;
    put_bytes(out, &v.slh_dsa_signature)?;
    Ok(())
}

fn decode_signature(c: &mut Cursor<'_>) -> Result<DualPqSignature, &'static str> {
    let v = DualPqSignature {
        ml_dsa_signature: c.bytes(ML_DSA_87_SIGNATURE_BYTES)?,
        slh_dsa_signature: c.bytes(SLH_DSA_SHAKE_256S_SIGNATURE_BYTES)?,
    };
    v.validate()?;
    Ok(v)
}

fn encode_radio(out: &mut Vec<u8>, v: &RadioCapabilities) -> Result<(), &'static str> {
    v.validate()?;
    out.extend_from_slice(&v.frequency_hz.to_be_bytes());
    out.extend_from_slice(&v.bandwidth_hz.to_be_bytes());
    put_bytes(out, v.modem.as_bytes())?;
    Ok(())
}

fn decode_radio(c: &mut Cursor<'_>) -> Result<RadioCapabilities, &'static str> {
    let frequency_hz = c.u64()?;
    let bandwidth_hz = c.u32()?;
    let modem_bytes = c.bytes(64)?;
    let modem = String::from_utf8(modem_bytes).map_err(|_| "invalid modem UTF-8")?;
    let v = RadioCapabilities {
        frequency_hz,
        bandwidth_hz,
        modem,
    };
    v.validate()?;
    Ok(v)
}

fn put_optional_root(out: &mut Vec<u8>, root: Option<[u8; 32]>) {
    match root {
        Some(root) => {
            out.push(1);
            out.extend_from_slice(&root);
        }
        None => out.push(0),
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), &'static str> {
    put_u32(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_u32(out: &mut Vec<u8>, value: usize) -> Result<(), &'static str> {
    let value = u32::try_from(value).map_err(|_| "wire length overflow")?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take_exact(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        let end = self.offset.checked_add(len).ok_or("wire offset overflow")?;
        if end > self.bytes.len() {
            return Err("truncated wire message");
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        Ok(self.take_exact(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        Ok(u16::from_be_bytes(
            self.take_exact(2)?.try_into().map_err(|_| "u16 decode")?,
        ))
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_be_bytes(
            self.take_exact(4)?.try_into().map_err(|_| "u32 decode")?,
        ))
    }

    fn u64(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_be_bytes(
            self.take_exact(8)?.try_into().map_err(|_| "u64 decode")?,
        ))
    }

    fn array_32(&mut self) -> Result<[u8; 32], &'static str> {
        self.take_exact(32)?
            .try_into()
            .map_err(|_| "32-byte decode")
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, &'static str> {
        let len = self.u32()? as usize;
        if len > max {
            return Err("wire field exceeds maximum");
        }
        Ok(self.take_exact(len)?.to_vec())
    }

    fn optional_root(&mut self) -> Result<Option<[u8; 32]>, &'static str> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.array_32()?)),
            _ => Err("invalid optional-root tag"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PqIdentity;
    use crate::protocol::{accept_server, start_client};

    fn caps() -> RadioCapabilities {
        RadioCapabilities {
            frequency_hz: 915_000_000,
            bandwidth_hz: 125_000,
            modem: "WIRE-TEST".into(),
        }
    }

    #[test]
    fn client_hello_wire_roundtrip() {
        let id = PqIdentity::generate().expect("identity");
        let client = start_client(&id, 7, caps(), None, None).expect("client");
        let encoded = encode_message(&WireMessage::ClientHello(client.hello.clone())).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(decoded, WireMessage::ClientHello(client.hello));
    }

    #[test]
    fn server_hello_wire_roundtrip() {
        let alice = PqIdentity::generate().expect("alice");
        let bob = PqIdentity::generate().expect("bob");
        let client = start_client(&alice, 7, caps(), None, None).expect("client");
        let server = accept_server(&bob, &client.hello, caps(), None, None).expect("server");
        let message = WireMessage::ServerHello(server.authenticated_hello.clone());
        let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
        assert_eq!(decoded, message);
    }
}
