use sha2::{Digest, Sha256};

pub trait RadioLink {
    fn mtu(&self) -> usize;
    fn send(&mut self, frame: &[u8]) -> Result<(), &'static str>;
    fn receive(&mut self) -> Result<Vec<u8>, &'static str>;
    fn link_fingerprint(&self) -> [u8;32];
}

#[derive(Debug, Default)]
pub struct LoopbackRadio {
    mtu: usize,
    queue: Vec<Vec<u8>>,
}

impl LoopbackRadio {
    pub fn new(mtu:usize)->Result<Self,&'static str>{
        if mtu<64 { return Err("MTU too small"); }
        Ok(Self{mtu,queue:Vec::new()})
    }
}

impl RadioLink for LoopbackRadio {
    fn mtu(&self)->usize{self.mtu}

    fn send(&mut self,frame:&[u8])->Result<(),&'static str>{
        if frame.len()>self.mtu{return Err("frame exceeds radio MTU");}
        self.queue.push(frame.to_vec());
        Ok(())
    }

    fn receive(&mut self)->Result<Vec<u8>,&'static str>{
        if self.queue.is_empty(){return Err("no frame available");}
        Ok(self.queue.remove(0))
    }

    fn link_fingerprint(&self)->[u8;32]{
        let mut h=Sha256::new();
        h.update(b"SYNERGY/PQ-RADIO/LINK/V1\0");
        h.update((self.mtu as u64).to_be_bytes());
        h.finalize().into()
    }
}


/// Physical byte-stream radio adapter.
///
/// This adapter works with any blocking stream implementing std::io::Read +
/// std::io::Write: UART/USB serial modems, TCP-connected SDR daemons, virtual
/// COM ports, or vendor SDK wrappers exposed as a byte stream.
///
/// Framing is deterministic: 4-byte big-endian length followed by payload.
/// Cryptographic authentication remains in protocol::EncryptedRadioFrame.
pub struct StreamRadio<T> {
    io: T,
    mtu: usize,
    fingerprint: [u8; 32],
}

impl<T> StreamRadio<T> {
    pub fn new(io: T, mtu: usize, device_descriptor: &[u8]) -> Result<Self, &'static str> {
        if mtu < 64 || mtu > crate::protocol::MAX_FRAME_BYTES + 4096 {
            return Err("invalid physical radio MTU");
        }
        if device_descriptor.is_empty() {
            return Err("physical radio device descriptor required");
        }
        let mut h = Sha256::new();
        h.update(b"SYNERGY/PQ-RADIO/PHYSICAL-LINK/V1\0");
        h.update((mtu as u64).to_be_bytes());
        h.update((device_descriptor.len() as u64).to_be_bytes());
        h.update(device_descriptor);
        let fingerprint = h.finalize().into();
        Ok(Self { io, mtu, fingerprint })
    }

    pub fn into_inner(self) -> T {
        self.io
    }
}

impl<T: std::io::Read + std::io::Write> RadioLink for StreamRadio<T> {
    fn mtu(&self) -> usize {
        self.mtu
    }

    fn send(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        if frame.len() > self.mtu {
            return Err("frame exceeds physical radio MTU");
        }
        let len = u32::try_from(frame.len()).map_err(|_| "frame length overflow")?;
        self.io
            .write_all(&len.to_be_bytes())
            .map_err(|_| "physical radio length write failed")?;
        self.io
            .write_all(frame)
            .map_err(|_| "physical radio payload write failed")?;
        self.io.flush().map_err(|_| "physical radio flush failed")?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8>, &'static str> {
        let mut len_bytes = [0u8; 4];
        self.io
            .read_exact(&mut len_bytes)
            .map_err(|_| "physical radio length read failed")?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > self.mtu {
            return Err("received frame exceeds physical radio MTU");
        }
        let mut frame = vec![0u8; len];
        self.io
            .read_exact(&mut frame)
            .map_err(|_| "physical radio payload read failed")?;
        Ok(frame)
    }

    fn link_fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;

    #[derive(Default)]
    struct MemoryDuplex {
        bytes: std::io::Cursor<Vec<u8>>,
    }

    impl std::io::Read for MemoryDuplex {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.bytes.read(buf)
        }
    }

    impl std::io::Write for MemoryDuplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes.get_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stream_radio_frames_physical_byte_stream() {
        let io = MemoryDuplex::default();
        let mut radio = StreamRadio::new(io, 1024, b"test-uart").expect("radio");
        radio.send(b"abc").expect("send");
        let mut io = radio.into_inner();
        io.bytes.set_position(0);
        let mut radio = StreamRadio::new(io, 1024, b"test-uart").expect("radio");
        assert_eq!(radio.receive().expect("receive"), b"abc");
    }
}
