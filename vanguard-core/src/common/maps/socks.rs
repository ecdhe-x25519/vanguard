#[cfg(feature = "userspace")]
use super::*;

#[cfg(feature = "userspace")]
use std::os::fd::AsRawFd;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct SockKey {
    pub local_ip: EbpfIp,
    pub remote_ip: EbpfIp,
    pub local_port: u32,
    pub remote_port: u32,
    pub protocol: IpProto,
}

#[cfg(feature = "userspace")]
unsafe impl crate::common::commons::Pod for SockKey {}

pub struct SockMapMap {
    map: SockMap<MapData>
}
impl SockMapMap {
    pub fn init(bpf: &mut Ebpf) -> Result<Self, VanguardError> {
        let map = get_map!(bpf, "SOCK_MAP", SockMap, SockMap<MapData>)?;
        Ok( Self { map })
    }

    pub fn add(&mut self, index: u32, socket: impl AsRawFd) -> Result<(), VanguardError> {
        self.map.set(index, &socket, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        
        Ok(())
    }

    pub fn del(&mut self, index: u32) -> Result<(), VanguardError> {
        self.map.clear_index(&index)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;

        Ok(())
    }
}

pub struct SockHashMap {
    map: SockHash<MapData, SockKey>
}

impl SockHashMap {
    pub fn init(bpf: &mut Ebpf) -> Result<Self, VanguardError> {
        let map = get_map!(bpf, "SOCK_HASH", SockHash, SockHash<MapData, SockKey>)?;
        Ok( Self { map })
    }

    pub fn add(&mut self, key: SockKey, value: impl AsRawFd) -> Result<(), VanguardError> {
        self.map.insert(key, value, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;

        Ok(())
    }

    pub fn del(&mut self, key: SockKey) -> Result<(), VanguardError> {
        self.map.remove(&key)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;

        Ok(())
    }
}