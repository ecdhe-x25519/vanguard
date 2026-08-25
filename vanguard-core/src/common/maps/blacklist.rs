#[cfg(feature = "userspace")]
use crate::get_map;

#[cfg(feature = "userspace")]
use crate::{
    common::{commons::*, ip::*},
    error::VanguardError
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockEvent {
    pub ip: EbpfNet,
    pad: [u8; 4],
}
#[cfg(feature = "userspace")]
unsafe impl Pod for BlockEvent {}

#[cfg(feature = "userspace")]
pub struct BlocklistMap;

#[cfg(feature = "userspace")]
impl BlocklistMap {
    pub fn get(bpf: &mut Ebpf) -> Result<LpmTrie<MapData, EbpfIp, u8>, VanguardError> {
        get_map!(bpf, "BLACKLIST", LpmTrie, LpmTrie<MapData, EbpfIp, u8>)
    }

    pub fn is_blocked(map: &LpmTrie<MapData, EbpfIp, u8>, ip: EbpfNet) -> bool {
        let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
        map.get(&key, 0).is_ok()
    }

    pub fn block(bpf: &mut Ebpf, ip: EbpfNet) -> Result<(), VanguardError> {        
        let mut map = Self::get(bpf)?;

        if Self::is_blocked(&map, ip) {
            return Ok(());
        } else {
            let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
            map.insert(&key, 1, 0)
                .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        }

        Ok(())
    }

    pub fn unblock(bpf: &mut Ebpf, ip: EbpfNet) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;

        if !Self::is_blocked(&map, ip) {
            return Ok(());
        } else {
            let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
            map.remove(&key)
                .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        }
        Ok(())
    }
}