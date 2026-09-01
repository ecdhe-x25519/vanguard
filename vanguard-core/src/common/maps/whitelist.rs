#[cfg(feature = "userspace")]
use super::*;

#[cfg(feature = "userspace")]
pub struct WhitelistMap {
    map: LpmTrie<MapData, EbpfIp, u8>,
}

#[cfg(feature = "userspace")]
impl WhitelistMap {
    pub fn get(bpf: &mut Ebpf) -> Result<Self, VanguardError> {
        let map = get_map!(bpf, "WHITELIST", LpmTrie, LpmTrie<MapData, EbpfIp, u8>)?;
        Ok(Self { map })
    }

    pub fn is_white(&self, ip: EbpfNet) -> bool {
        let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
        self.map.get(&key, 0).is_ok()
    }

    pub fn insert(&mut self, ip: EbpfNet) -> Result<(), VanguardError> {
        if self.is_white(ip) {
            return Ok(());
        } else {
            let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
            self.map.insert(&key, 0, 0)
                .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        }

        Ok(())
    }

    pub fn remove(&mut self, ip: EbpfNet) -> Result<(), VanguardError> {
        if !self.is_white(ip) {
            return Ok(());
        } else {
            let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
            self.map.remove(&key)
                .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        }

        Ok(())
    }
}