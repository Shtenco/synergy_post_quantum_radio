use sha2::{Digest, Sha256};

use crate::crypto::PqIdentity;
use crate::pi_pq::PiPqEvidence;
use crate::protocol::{
    accept_server, finish_client, finish_server, start_client, RadioCapabilities, RadioSession,
};
use crate::quantum::TeleportationReceipt;
use crate::radio::RadioLink;
use crate::wire::{receive_wire_message, send_wire_message, WireMessage};

pub fn client_handshake<L: RadioLink>(
    link: &mut L,
    identity: &PqIdentity,
    epoch: u64,
    radio: RadioCapabilities,
    teleportation: Option<&TeleportationReceipt>,
    pi_pq: Option<&PiPqEvidence>,
) -> Result<RadioSession, &'static str> {
    let state = start_client(identity, epoch, radio, teleportation, pi_pq)?;
    send_wire_message(link, &WireMessage::ClientHello(state.hello.clone()))?;

    let server = match receive_wire_message(link)? {
        WireMessage::ServerHello(server) => server,
        _ => return Err("expected authenticated server hello"),
    };

    let (finish, session) = finish_client(identity, &state, &server)?;
    send_wire_message(link, &WireMessage::ClientFinish(finish))?;
    Ok(session)
}

pub fn server_handshake<L: RadioLink>(
    link: &mut L,
    identity: &PqIdentity,
    radio: RadioCapabilities,
    teleportation: Option<&TeleportationReceipt>,
    pi_pq: Option<&PiPqEvidence>,
) -> Result<RadioSession, &'static str> {
    let client = match receive_wire_message(link)? {
        WireMessage::ClientHello(client) => client,
        _ => return Err("expected client hello"),
    };

    let state = accept_server(identity, &client, radio, teleportation, pi_pq)?;
    send_wire_message(
        link,
        &WireMessage::ServerHello(state.authenticated_hello.clone()),
    )?;

    let finish = match receive_wire_message(link)? {
        WireMessage::ClientFinish(finish) => finish,
        _ => return Err("expected client finish"),
    };
    finish_server(&state, &client, &finish)
}

pub fn session_aad_root(session: &RadioSession) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SYNERGY/PQ-RADIO/APPLICATION-AAD/V1\0");
    h.update(session.transcript_root);
    h.finalize().into()
}

pub fn send_encrypted<L: RadioLink>(
    link: &mut L,
    session: &mut RadioSession,
    plaintext: &[u8],
) -> Result<(), &'static str> {
    let aad_root = session_aad_root(session);
    let frame = session.encrypt(aad_root, plaintext)?;
    send_wire_message(link, &WireMessage::EncryptedFrame(frame))
}

pub fn receive_encrypted<L: RadioLink>(
    link: &mut L,
    session: &mut RadioSession,
) -> Result<Vec<u8>, &'static str> {
    let frame = match receive_wire_message(link)? {
        WireMessage::EncryptedFrame(frame) => frame,
        _ => return Err("expected encrypted radio frame"),
    };
    if frame.aad_root != session_aad_root(session) {
        return Err("application AAD root mismatch");
    }
    session.decrypt(&frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radio::RadioLink;
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::thread;

    struct ChannelRadio {
        tx: Sender<Vec<u8>>,
        rx: Receiver<Vec<u8>>,
        mtu: usize,
        fingerprint: [u8; 32],
    }

    impl RadioLink for ChannelRadio {
        fn mtu(&self) -> usize {
            self.mtu
        }

        fn send(&mut self, frame: &[u8]) -> Result<(), &'static str> {
            if frame.len() > self.mtu {
                return Err("test frame exceeds MTU");
            }
            self.tx.send(frame.to_vec()).map_err(|_| "test send failed")
        }

        fn receive(&mut self) -> Result<Vec<u8>, &'static str> {
            self.rx.recv().map_err(|_| "test receive failed")
        }

        fn link_fingerprint(&self) -> [u8; 32] {
            self.fingerprint
        }
    }

    fn pair(mtu: usize) -> (ChannelRadio, ChannelRadio) {
        let (a_tx, b_rx) = mpsc::channel();
        let (b_tx, a_rx) = mpsc::channel();
        (
            ChannelRadio {
                tx: a_tx,
                rx: a_rx,
                mtu,
                fingerprint: [1; 32],
            },
            ChannelRadio {
                tx: b_tx,
                rx: b_rx,
                mtu,
                fingerprint: [2; 32],
            },
        )
    }

    fn caps(name: &str) -> RadioCapabilities {
        RadioCapabilities {
            frequency_hz: 915_000_000,
            bandwidth_hz: 125_000,
            modem: name.into(),
        }
    }

    #[test]
    fn two_nodes_complete_full_pq_handshake_over_tiny_mtu() {
        let (mut client_link, mut server_link) = pair(128);

        let server = thread::spawn(move || {
            let bob = PqIdentity::generate().expect("bob identity");
            let mut session =
                server_handshake(&mut server_link, &bob, caps("NODE-B"), None, None)
                    .expect("server handshake");
            let received =
                receive_encrypted(&mut server_link, &mut session).expect("server receive");
            assert_eq!(received, b"R3 PHYSICAL TRANSPORT TEST");
            send_encrypted(&mut server_link, &mut session, b"ACK").expect("server ack");
        });

        let alice = PqIdentity::generate().expect("alice identity");
        let mut session =
            client_handshake(&mut client_link, &alice, 1, caps("NODE-A"), None, None)
                .expect("client handshake");
        send_encrypted(
            &mut client_link,
            &mut session,
            b"R3 PHYSICAL TRANSPORT TEST",
        )
        .expect("client send");
        let ack = receive_encrypted(&mut client_link, &mut session).expect("client ack");
        assert_eq!(ack, b"ACK");

        server.join().expect("server thread");
    }
}
