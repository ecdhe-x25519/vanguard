#[cfg(feature = "userspace")]
use super::*;

#[cfg(feature = "userspace")]
pub struct Maglev {
    pool: Array<MapData, EbpfIp>,
}

#[cfg(feature = "userspace")]
impl Maglev {
    pub fn get(bpf: &mut Ebpf) -> Result<Self, VanguardError> {
        let pool = get_map!(bpf, "MAGLEV_POOL", Array, Array<MapData, EbpfIp>)?;
        Ok(Self { pool })
    }
}