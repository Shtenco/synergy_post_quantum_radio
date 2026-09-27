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
