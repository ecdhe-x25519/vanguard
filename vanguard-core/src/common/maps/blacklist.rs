#[cfg(feature = "userspace")]
use super::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockEvent {
    pub ip: EbpfNet,
    pad: [u8; 4],
}
#[cfg(feature = "userspace")]
unsafe impl Pod for BlockEvent {}

#[cfg(feature = "userspace")]
pub struct BlocklistMap {
    map: LpmTrie<MapData, EbpfIp, u8>
}

#[cfg(feature = "userspace")]
impl BlocklistMap {
    pub fn init(bpf: &mut Ebpf) -> Result<Self, VanguardError> {
        let map = get_map!(bpf, "BLACKLIST", LpmTrie, LpmTrie<MapData, EbpfIp, u8>)?;
        Ok(Self { map })
    }

    pub fn is_blocked(&self, ip: EbpfNet) -> bool {
        let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
        self.map.get(&key, 0).is_ok()
    }

    pub fn block(&mut self, ip: EbpfNet) -> Result<(), VanguardError> {
        if self.is_blocked(ip) {
            return Ok(());
        } else {
            let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
            self.map.insert(&key, 1, 0)
                .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        }

        Ok(())
    }

    pub fn unblock(&mut self, ip: EbpfNet) -> Result<(), VanguardError> {
        if !self.is_blocked(ip) {
            return Ok(());
        } else {
            let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
            self.map.remove(&key)
                .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        }
        Ok(())
    }
}