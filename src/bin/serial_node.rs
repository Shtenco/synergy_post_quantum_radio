use std::env;
use std::time::Duration;

use synergy_post_quantum_radio::crypto::PqIdentity;
use synergy_post_quantum_radio::node::{
    client_handshake, receive_encrypted, send_encrypted, server_handshake,
};
use synergy_post_quantum_radio::protocol::RadioCapabilities;
use synergy_post_quantum_radio::radio::StreamRadio;

fn usage() -> ! {
    eprintln!(
        "usage: synergy-pq-radio-serial-node <client|server> <serial-port> <baud> <mtu> <frequency_hz> <bandwidth_hz> [message]"
    );
    std::process::exit(2);
}

fn capabilities(port: &str, frequency_hz: u64, bandwidth_hz: u32) -> RadioCapabilities {
    RadioCapabilities {
        frequency_hz,
        bandwidth_hz,
        modem: format!("SERIAL:{}", port).chars().take(64).collect(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 7 {
        usage();
    }

    let role = args[1].as_str();
    let port_name = &args[2];
    let baud: u32 = args[3].parse()?;
    let mtu: usize = args[4].parse()?;
    let frequency_hz: u64 = args[5].parse()?;
    let bandwidth_hz: u32 = args[6].parse()?;
    let message = args
        .get(7)
        .cloned()
        .unwrap_or_else(|| "SYNERGY R3 PQ RADIO".to_string());

    let port = serialport::new(port_name, baud)
        .timeout(Duration::from_secs(120))
        .open()?;

    let descriptor = format!("serial:{}:{}", port_name, baud);
    let mut radio = StreamRadio::new(port, mtu, descriptor.as_bytes())?;
    let identity = PqIdentity::generate()?;

    match role {
        "client" => {
            let mut session = client_handshake(
                &mut radio,
                &identity,
                1,
                capabilities(port_name, frequency_hz, bandwidth_hz),
                None,
                None,
            )?;
            send_encrypted(&mut radio, &mut session, message.as_bytes())?;
            let reply = receive_encrypted(&mut radio, &mut session)?;
            println!("peer_reply={}", String::from_utf8_lossy(&reply));
        }
        "server" => {
            let mut session =
                server_handshake(&mut radio, &identity, capabilities(port_name, frequency_hz, bandwidth_hz), None, None)?;
            let incoming = receive_encrypted(&mut radio, &mut session)?;
            println!("peer_message={}", String::from_utf8_lossy(&incoming));
            send_encrypted(&mut radio, &mut session, b"ACK")?;
        }
        _ => usage(),
    }

    Ok(())
}
